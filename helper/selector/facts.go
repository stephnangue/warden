package selector

import (
	"encoding/json"
	"math"
	"slices"
	"strconv"
	"strings"
)

// Facts is what a mount verified about one credential, keyed by raw names:
// claims for a token, fields for a certificate or a service account. Lookup
// returns an empty Cursor when the key is absent or its value is not a scalar
// or an array of scalars.
type Facts interface {
	Lookup(key Key) Cursor
}

// Kind is the type of a Scalar.
type Kind uint8

// Scalar kinds. The zero Kind marks no value.
const (
	KindInvalid Kind = iota
	KindString
	KindNumber
	KindBool
)

// Scalar is one fact value. Only the field its Kind names is set.
type Scalar struct {
	Kind Kind
	S    string
	N    float64
	B    bool
}

// Cursor walks the values of one fact. It is returned by value and holds no
// pointer to anything but the facts it reads, so walking one does not allocate.
// The zero Cursor yields nothing.
type Cursor struct {
	strs []string // a Table field's values
	arr  []any    // a claim array; non-scalar elements are skipped
	one  Scalar   // a single value, when strs and arr are nil
	n, i int      // values to walk, and the next one
}

// Next returns the next value and true, or false once the values run out.
func (c *Cursor) Next() (Scalar, bool) {
	for c.i < c.n {
		i := c.i
		c.i++
		switch {
		case c.strs != nil:
			return Scalar{Kind: KindString, S: c.strs[i]}, true
		case c.arr != nil:
			if s, ok := scalarOf(c.arr[i]); ok {
				return s, true
			}
		default:
			return c.one, true
		}
	}
	return Scalar{}, false
}

// One returns a Cursor yielding the single string s.
func One(s string) Cursor {
	return Cursor{one: Scalar{Kind: KindString, S: s}, n: 1}
}

// scalarOf converts a value encoding/json decoded to a Scalar. Objects, arrays,
// null and every type encoding/json does not produce are not scalars.
func scalarOf(v any) (Scalar, bool) {
	switch v := v.(type) {
	case string:
		return Scalar{Kind: KindString, S: v}, true
	case float64:
		return Scalar{Kind: KindNumber, N: v}, true
	case bool:
		return Scalar{Kind: KindBool, B: v}, true
	case json.Number:
		f, err := strconv.ParseFloat(string(v), 64)
		if err != nil {
			return Scalar{}, false
		}
		return Scalar{Kind: KindNumber, N: f}, true
	}
	return Scalar{}, false
}

// cursorOf returns a Cursor over a JSON-decoded value: one value for a scalar,
// the scalar elements of an array, nothing for anything else.
func cursorOf(v any) Cursor {
	if arr, ok := v.([]any); ok {
		return Cursor{arr: arr, n: len(arr)}
	}
	if s, ok := scalarOf(v); ok {
		return Cursor{one: s, n: 1}
	}
	return Cursor{}
}

// Claims are facts held as a JSON-decoded object, as a token's claims are.
type Claims struct {
	m map[string]any
}

// NewClaims adopts m without copying it; the caller must not modify m, or
// anything it holds, afterwards. m must come from encoding/json decoding (with
// or without UseNumber): only map[string]any, []any, string, float64,
// json.Number and bool are read, and a value of any other Go type, such as an
// int or a []string, is invisible.
func NewClaims(m map[string]any) *Claims { return &Claims{m: m} }

// Lookup returns the claim key names. A plain name is a top-level claim. A
// pointer walks objects by member name and arrays by index, where an index is
// "0" or a decimal number without a leading zero; a step through a scalar, a
// missing member or an index out of range yields nothing.
func (c *Claims) Lookup(key Key) Cursor {
	if c == nil {
		return Cursor{}
	}
	if key.Path == nil {
		v, ok := c.m[key.Name]
		if !ok {
			return Cursor{}
		}
		return cursorOf(v)
	}
	var cur any = c.m
	for _, tok := range key.Path {
		switch node := cur.(type) {
		case map[string]any:
			v, ok := node[tok]
			if !ok {
				return Cursor{}
			}
			cur = v
		case []any:
			idx, ok := arrayIndex(tok)
			if !ok || idx >= len(node) {
				return Cursor{}
			}
			cur = node[idx]
		default:
			return Cursor{}
		}
	}
	return cursorOf(cur)
}

// arrayIndex parses an RFC 6901 array index: "0", or digits without a leading
// zero. It refuses anything else, including "-" (one past the end).
func arrayIndex(tok string) (int, bool) {
	if tok == "" || len(tok) > 9 || (tok[0] == '0' && len(tok) > 1) {
		return 0, false
	}
	n := 0
	for i := 0; i < len(tok); i++ {
		c := tok[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}

// Field is one named, string-valued fact of a Table.
type Field struct {
	Name   string
	Values []string
}

// Table holds facts as a small set of named string fields, as a certificate
// or a service account yields. Fields are sorted by name.
type Table struct {
	fields []Field
}

// NewTable copies fields into a Table, so later changes to the arguments do not
// reach it. Field names are fixed by the auth method, so NewTable panics on a
// duplicate name or on more than MaxTableFields fields.
func NewTable(fields ...Field) *Table {
	if len(fields) > MaxTableFields {
		panic("selector: too many table fields")
	}
	total := 0
	for _, f := range fields {
		total += len(f.Values)
	}
	values := make([]string, 0, total)
	out := make([]Field, len(fields))
	for i, f := range fields {
		start := len(values)
		values = append(values, f.Values...)
		out[i] = Field{Name: f.Name, Values: values[start:len(values):len(values)]}
	}
	slices.SortFunc(out, func(a, b Field) int { return strings.Compare(a.Name, b.Name) })
	for i := 1; i < len(out); i++ {
		if out[i].Name == out[i-1].Name {
			panic("selector: duplicate table field " + strconv.Quote(out[i].Name))
		}
	}
	return &Table{fields: out}
}

// Bytes returns the length of every field name and value t holds, summed: an
// estimate of the memory it retains, for cache accounting. A nil Table holds
// nothing.
func (t *Table) Bytes() int64 {
	if t == nil {
		return 0
	}
	var n int64
	for i := range t.fields {
		n += int64(len(t.fields[i].Name))
		for _, v := range t.fields[i].Values {
			n += int64(len(v))
		}
	}
	return n
}

// Lookup returns the values of the field key names. A JSON pointer yields
// nothing: a Table has no nesting.
func (t *Table) Lookup(key Key) Cursor {
	if t == nil || key.Path != nil {
		return Cursor{}
	}
	for i := range t.fields {
		f := &t.fields[i]
		if f.Name == key.Name {
			if len(f.Values) == 0 {
				return Cursor{}
			}
			return Cursor{strs: f.Values, n: len(f.Values)}
		}
	}
	return Cursor{}
}

// FormatScalar appends the one string rendering of v to dst and returns the
// extended buffer. Strings are appended as is and booleans as true or false.
// Numbers render as JSON encodes them: integers without a fraction or exponent
// (10, -7, 9007199254740992), other values in the shortest form that reads back
// exactly (1.5), and an exponent only from 1e21 up or below 1e-6 (1e+21).
// Negative zero renders as -0. NaN and ±Inf cannot come from JSON; they render
// as strconv formats them (NaN, +Inf, -Inf). A 32-byte buffer holds any number
// or boolean, so callers rendering into a stack array do not allocate.
func FormatScalar(dst []byte, v Scalar) []byte {
	switch v.Kind {
	case KindString:
		return append(dst, v.S...)
	case KindBool:
		return strconv.AppendBool(dst, v.B)
	case KindNumber:
		return appendNumber(dst, v.N)
	}
	return dst
}

// AppendValues appends every value cur yields to dst, each rendered by
// FormatScalar and separated by sep, and returns the extended buffer. It drains
// cur. A dst with room for the result is not reallocated, so rendering a fact
// into a reused buffer does not allocate.
func AppendValues(dst []byte, cur *Cursor, sep byte) []byte {
	first := true
	for v, ok := cur.Next(); ok; v, ok = cur.Next() {
		if !first {
			dst = append(dst, sep)
		}
		first = false
		dst = FormatScalar(dst, v)
	}
	return dst
}

// appendNumber formats f as encoding/json does.
func appendNumber(dst []byte, f float64) []byte {
	format := byte('f')
	if abs := math.Abs(f); abs != 0 && (abs < 1e-6 || abs >= 1e21) {
		format = 'e'
	}
	dst = strconv.AppendFloat(dst, f, format, -1, 64)
	if format == 'e' {
		// Turn e-09 into e-9, as encoding/json does.
		if n := len(dst); n >= 4 && dst[n-4] == 'e' && dst[n-3] == '-' && dst[n-2] == '0' {
			dst[n-2] = dst[n-1]
			dst = dst[:n-1]
		}
	}
	return dst
}
