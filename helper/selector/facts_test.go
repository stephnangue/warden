package selector

import (
	"encoding/json"
	"math"
	"slices"
	"strconv"
	"sync"
	"testing"
)

func mustKey(t testing.TB, s string) Key {
	t.Helper()
	k, err := ParseKey(s)
	if err != nil {
		t.Fatalf("ParseKey(%q): %v", s, err)
	}
	return k
}

// collect drains a cursor.
func collect(c Cursor) []Scalar {
	var out []Scalar
	for v, ok := c.Next(); ok; v, ok = c.Next() {
		out = append(out, v)
	}
	return out
}

func str(s string) Scalar   { return Scalar{Kind: KindString, S: s} }
func num(n float64) Scalar  { return Scalar{Kind: KindNumber, N: n} }
func boolean(b bool) Scalar { return Scalar{Kind: KindBool, B: b} }

func decodeClaims(t testing.TB, js string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(js), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestCursor(t *testing.T) {
	if got := collect(Cursor{}); got != nil {
		t.Fatalf("zero Cursor yielded %v", got)
	}
	if got := collect(One("auth/jwt/")); !slices.Equal(got, []Scalar{str("auth/jwt/")}) {
		t.Fatalf("One yielded %v", got)
	}
	c := One("x")
	c.Next()
	if _, ok := c.Next(); ok {
		t.Fatal("a drained cursor yielded again")
	}
}

func TestClaimsLookup(t *testing.T) {
	claims := NewClaims(decodeClaims(t, `{
		"sub": "agent-1",
		"n": 10,
		"f": 1.5,
		"ok": true,
		"null": null,
		"groups": ["a", {"x": 1}, 2, false, ["nested"], null, "b"],
		"obj": {"k": "v"},
		"empty": [],
		"deployment": {"env": "prod", "tags": ["blue", "green"], "n": {"deep": 7}},
		"a/b": {"~c": "escaped"},
		"https://example.com/env": "ns-claim",
		"": "blank"
	}`))
	cases := []struct {
		key  string
		want []Scalar
	}{
		{"sub", []Scalar{str("agent-1")}},
		{"n", []Scalar{num(10)}},
		{"f", []Scalar{num(1.5)}},
		{"ok", []Scalar{boolean(true)}},
		{"null", nil},
		{"missing", nil},
		{"groups", []Scalar{str("a"), num(2), boolean(false), str("b")}},
		{"obj", nil},
		{"empty", nil},
		{"https://example.com/env", []Scalar{str("ns-claim")}},
		{"/", []Scalar{str("blank")}},
		{"/deployment/env", []Scalar{str("prod")}},
		{"/deployment/tags", []Scalar{str("blue"), str("green")}},
		{"/deployment/tags/1", []Scalar{str("green")}},
		{"/deployment/tags/2", nil},  // out of range
		{"/deployment/tags/01", nil}, // not an RFC 6901 index
		{"/deployment/tags/-", nil},
		{"/deployment/tags/x", nil},
		{"/deployment/n/deep", []Scalar{num(7)}},
		{"/deployment/missing", nil},
		{"/sub/x", nil}, // through a scalar
		{"/groups/1/x", []Scalar{num(1)}},
		{"/groups/4/0", []Scalar{str("nested")}},
		{"/a~1b/~0c", []Scalar{str("escaped")}},
		{"/deployment", nil}, // an object
	}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			if got := collect(claims.Lookup(mustKey(t, tc.key))); !slices.Equal(got, tc.want) {
				t.Fatalf("Lookup(%q) = %v; want %v", tc.key, got, tc.want)
			}
		})
	}
	var nilClaims *Claims
	if got := collect(nilClaims.Lookup(mustKey(t, "sub"))); got != nil {
		t.Fatalf("nil Claims yielded %v", got)
	}
}

// Only the types encoding/json produces are read; anything else is invisible.
func TestClaimsLookup_GoTypes(t *testing.T) {
	claims := NewClaims(map[string]any{
		"jn":   json.Number("42"),
		"bad":  json.Number("x"),
		"i":    7,
		"i64":  int64(-3),
		"f32":  float32(2.5),
		"strs": []string{"a", "b"},
		"smap": map[string]string{"k": "v"},
		"arr":  []any{"a", 7, "b"},
	})
	for key, want := range map[string][]Scalar{
		"jn":      {num(42)},
		"bad":     nil,
		"i":       nil,
		"i64":     nil,
		"f32":     nil,
		"strs":    nil,
		"smap":    nil,
		"/smap/k": nil,
		"arr":     {str("a"), str("b")},
	} {
		if got := collect(claims.Lookup(mustKey(t, key))); !slices.Equal(got, want) {
			t.Errorf("Lookup(%q) = %v; want %v", key, got, want)
		}
	}
}

func TestTableLookup(t *testing.T) {
	tbl := NewTable(
		Field{Name: "username", Values: []string{"system:serviceaccount:ci:deployer"}},
		Field{Name: "groups", Values: []string{"system:serviceaccounts", "system:serviceaccounts:ci"}},
		Field{Name: "aud", Values: []string{"warden"}},
		Field{Name: "none"},
	)
	cases := map[string][]Scalar{
		"username": {str("system:serviceaccount:ci:deployer")},
		"groups":   {str("system:serviceaccounts"), str("system:serviceaccounts:ci")},
		"aud":      {str("warden")},
		"none":     nil,
		"absent":   nil,
		"/groups":  nil, // a table has no nesting
	}
	for key, want := range cases {
		if got := collect(tbl.Lookup(mustKey(t, key))); !slices.Equal(got, want) {
			t.Errorf("Lookup(%q) = %v; want %v", key, got, want)
		}
	}
	var nilTable *Table
	if got := collect(nilTable.Lookup(Key{Name: "aud"})); got != nil {
		t.Fatalf("nil Table yielded %v", got)
	}
}

func TestNewTable_Copies(t *testing.T) {
	values := []string{"a", "b"}
	fields := []Field{{Name: "f", Values: values}}
	tbl := NewTable(fields...)
	values[0] = "changed"
	fields[0].Name = "g"
	if got := collect(tbl.Lookup(Key{Name: "f"})); !slices.Equal(got, []Scalar{str("a"), str("b")}) {
		t.Fatalf("table changed with its input: %v", got)
	}
}

func TestNewTable_Panics(t *testing.T) {
	mustPanic := func(name string, fn func()) {
		t.Helper()
		defer func() {
			if recover() == nil {
				t.Errorf("%s: no panic", name)
			}
		}()
		fn()
	}
	mustPanic("duplicate", func() { NewTable(Field{Name: "a"}, Field{Name: "a"}) })
	mustPanic("too many", func() { NewTable(make([]Field, MaxTableFields+1)...) })
}

func TestFormatScalar(t *testing.T) {
	cases := []struct {
		in   Scalar
		want string
	}{
		{num(1), "1"},
		{num(-7), "-7"},
		{num(0), "0"},
		{num(10), "10"},
		{num(1.5), "1.5"},
		{num(-0.25), "-0.25"},
		{num(0.1), "0.1"},
		{num(1e20), "100000000000000000000"},
		{num(1e21), "1e+21"},
		{num(1.5e300), "1.5e+300"},
		{num(1e-6), "0.000001"},
		{num(1e-7), "1e-7"},
		{num(math.Ldexp(1, 53)), "9007199254740992"},
		{num(math.Ldexp(1, 53) + 2), "9007199254740994"},
		{num(-math.Ldexp(1, 53)), "-9007199254740992"},
		{num(math.Ldexp(1, 53) - 1), "9007199254740991"},
		{boolean(true), "true"},
		{boolean(false), "false"},
		{str("s"), "s"},
		{Scalar{}, ""},
	}
	for _, tc := range cases {
		var buf [32]byte
		if got := string(FormatScalar(buf[:0], tc.in)); got != tc.want {
			t.Errorf("FormatScalar(%+v) = %q; want %q", tc.in, got, tc.want)
		}
		if tc.in.Kind == KindNumber {
			// Numbers render as encoding/json renders them.
			js, _ := json.Marshal(tc.in.N)
			if string(js) != tc.want {
				t.Errorf("json renders %v as %s; FormatScalar as %s", tc.in.N, js, tc.want)
			}
		}
	}
	// Appends to what dst holds.
	if got := string(FormatScalar([]byte("n="), num(3))); got != "n=3" {
		t.Errorf("got %q", got)
	}
}

func TestFormatScalar_NegativeZeroAndNonFinite(t *testing.T) {
	for f, want := range map[float64]string{
		math.Copysign(0, -1): "-0",
		math.Inf(1):          "+Inf",
		math.Inf(-1):         "-Inf",
	} {
		if got := string(FormatScalar(nil, num(f))); got != want {
			t.Errorf("FormatScalar(%v) = %q; want %q", f, got, want)
		}
	}
	if got := string(FormatScalar(nil, num(math.NaN()))); got != "NaN" {
		t.Errorf("FormatScalar(NaN) = %q", got)
	}
}

func TestAppendValues(t *testing.T) {
	claims := NewClaims(decodeClaims(t, `{"groups":["a",{"x":1},2,true,"b"],"one":"x","n":1.5,"empty":[],"obj":{}}`))
	cases := map[string]string{
		"groups": "a,2,true,b",
		"one":    "x",
		"n":      "1.5",
		"empty":  "",
		"obj":    "",
		"absent": "",
	}
	for key, want := range cases {
		cur := claims.Lookup(mustKey(t, key))
		if got := string(AppendValues([]byte("k="), &cur, ',')); got != "k="+want {
			t.Errorf("AppendValues(%q) = %q; want %q", key, got, "k="+want)
		}
		if _, ok := cur.Next(); ok {
			t.Errorf("AppendValues(%q) left the cursor undrained", key)
		}
	}
	tbl := NewTable(Field{Name: "ou", Values: []string{"eng", "ops"}})
	cur := tbl.Lookup(Key{Name: "ou"})
	if got := string(AppendValues(nil, &cur, ';')); got != "eng;ops" {
		t.Errorf("table values joined as %q", got)
	}
}

func TestAppendValues_NoAllocs(t *testing.T) {
	claims := NewClaims(decodeClaims(t, `{"groups":["deployers","admins",42,false,0.5]}`))
	key := mustKey(t, "groups")
	buf := make([]byte, 0, 128)
	allocs := testing.AllocsPerRun(1000, func() {
		cur := claims.Lookup(key)
		buf = AppendValues(buf[:0], &cur, ',')
	})
	t.Logf("AppendValues into a buffer with room: %v allocs per run", allocs)
	if allocs != 0 {
		t.Fatalf("AppendValues allocates %v times per run", allocs)
	}
	if string(buf) != "deployers,admins,42,false,0.5" {
		t.Fatalf("got %q", buf)
	}
}

func TestFormatScalar_FitsStackBuffer(t *testing.T) {
	for _, f := range []float64{-math.MaxFloat64, math.SmallestNonzeroFloat64, -1.2345678901234567e-7, -123456789012345680000, -0.0000012345678901234567} {
		var buf [32]byte
		if out := FormatScalar(buf[:0], num(f)); &out[0] != &buf[0] {
			t.Errorf("%v (%s) does not fit 32 bytes", f, out)
		}
	}
}

func TestLookupNext_NoAllocs(t *testing.T) {
	groups := make([]any, 200)
	for i := range groups {
		groups[i] = "group-" + strconv.Itoa(i)
	}
	claims := NewClaims(map[string]any{
		"groups":     groups,
		"deployment": map[string]any{"env": "prod", "n": 7.0},
	})
	tbl := NewTable(Field{Name: "groups", Values: []string{"a", "b", "c"}})
	keys := []Key{mustKey(t, "groups"), mustKey(t, "/deployment/env"), mustKey(t, "/deployment/n"), mustKey(t, "/groups/199")}
	var facts Facts = claims
	var tfacts Facts = tbl
	n := 0
	allocs := testing.AllocsPerRun(1000, func() {
		for _, k := range keys {
			c := facts.Lookup(k)
			for _, ok := c.Next(); ok; _, ok = c.Next() {
				n++
			}
		}
		c := tfacts.Lookup(keys[0])
		for _, ok := c.Next(); ok; _, ok = c.Next() {
			n++
		}
	})
	t.Logf("Lookup+Next: %v allocs per run", allocs)
	if allocs != 0 {
		t.Fatalf("Lookup+Next allocates %v times per run", allocs)
	}
}

func TestFacts_ConcurrentReads(t *testing.T) {
	claims := NewClaims(decodeClaims(t, `{"sub":"a","groups":["x","y"],"d":{"e":[1,2]}}`))
	tbl := NewTable(Field{Name: "cn", Values: []string{"svc"}})
	keys := []Key{mustKey(t, "sub"), mustKey(t, "groups"), mustKey(t, "/d/e/1")}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 500 {
				for _, k := range keys {
					collect(claims.Lookup(k))
				}
				collect(tbl.Lookup(Key{Name: "cn"}))
			}
		}()
	}
	wg.Wait()
}
