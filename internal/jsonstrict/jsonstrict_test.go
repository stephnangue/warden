package jsonstrict

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDuplicateKey(t *testing.T) {
	keys := func(n int, extra string) string {
		var b strings.Builder
		b.WriteByte('{')
		for i := range n {
			fmt.Fprintf(&b, `"k%d":%d,`, i, i)
		}
		b.WriteString(extra)
		b.WriteByte('}')
		return b.String()
	}
	tests := []struct {
		name string
		json string
		dup  string // "" when none
	}{
		{"empty object", `{}`, ""},
		{"one key", `{"a":1}`, ""},
		{"a repeat", `{"a":1,"a":2}`, "a"},
		{"a repeat with whitespace", "{ \"a\" : 1 ,\n \"a\" : 2 }", "a"},
		{"the same key in a child", `{"a":1,"b":{"a":2}}`, ""},
		{"a repeat in a child", `{"a":{"b":1,"b":2}}`, "b"},
		{"a repeat after a child closes", `{"x":[1,{"y":1}],"x":2}`, "x"},
		{"the same key in siblings", `[{"a":1},{"a":1}]`, ""},
		{"a repeat in a top-level array", `[1,{"a":1,"a":2}]`, "a"},
		{"a key-like string value", `{"a":"\"a\":","b":"{\"b\":1,\"b\":2}"}`, ""},
		{"an escape spells the same key", `{"a":1,"\u0061":2}`, "a"},
		{"an escaped quote in a key", `{"a\"b":1,"a\"b":2}`, `a"b`},
		{"UTF-8 against its escape", `{"é":1,"\u00e9":2}`, "é"},
		{"invalid UTF-8 encoding/json decodes alike", "{\"a\xff\":1,\"a\xfe\":2}", "a\uFFFD"},
		{"lone surrogates decode alike", `{"\ud800":1,"\udc00":2}`, "\uFFFD"},
		{"a lone surrogate against invalid UTF-8", "{\"\\ud800\":1,\"\xff\":2}", "\uFFFD"},
		{"case is not folded", `{"A":1,"a":2}`, ""},
		{"many keys, none repeated", keys(40, `"z":0`), ""},
		{"many keys, a repeat past the linear scan", keys(40, `"k3":0`), "k3"},
		{"a repeat right at the switch to a map", keys(16, `"k0":0`), "k0"},
		{"a scalar", `"a"`, ""},
		{"a number", `12.5e3`, ""},
		{"deep nesting", strings.Repeat("[", 5000) + `{"a":1}` + strings.Repeat("]", 5000), ""},
		{"a repeat deep down", strings.Repeat(`{"a":`, 3000) + `{"b":1,"b":2}` + strings.Repeat("}", 3000), "b"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var v any
			require.NoError(t, json.Unmarshal([]byte(tc.json), &v), "the input must be valid JSON")
			key, found := DuplicateKey([]byte(tc.json))
			assert.Equal(t, tc.dup != "", found)
			assert.Equal(t, tc.dup, key)
			ref, refFound := referenceDuplicateKey([]byte(tc.json))
			assert.Equal(t, refFound, found, "agrees with the reference")
			assert.Equal(t, ref, key, "agrees with the reference")
		})
	}
}

// What a typical body costs: nothing, once the pool is warm.
func TestDuplicateKey_AllocatesNothing(t *testing.T) {
	if raceEnabled {
		t.Skip("sync.Pool drops put scanners on purpose under the race detector")
	}
	body := []byte(`{"message":{"subject":"Q3 plan","body":{"contentType":"Text","content":"see attached"},` +
		`"toRecipients":[{"emailAddress":{"address":"ann@example.com"}},{"emailAddress":{"address":"bo@example.com"}}]},` +
		`"saveToSentItems":true,"labels":["a","b"],"n":12.5,"x":null}`)
	allocs := testing.AllocsPerRun(100, func() { _, _ = DuplicateKey(body) })
	assert.Zero(t, allocs)
}

// The scanner reads keys exactly as a token-by-token decode does.
func FuzzDuplicateKey(f *testing.F) {
	for _, s := range []string{
		`{}`, `{"a":1,"a":2}`, `{"a":{"a":1}}`, `[{"a":1},{"a":1}]`, `{"a":1,"\u0061":2}`,
		"{\"a\xff\":1,\"a\xfe\":2}", `{"x":[1,{"y":1}],"x":2}`, `{"a":"\"a\":"}`, `"s"`, `[1,2]`,
		`{"a\"b":1,"a\\":2}`, "{\"\\ud800\":1,\"\\udc00\":2}",
		// Past the linear scan, so the fuzzer reaches the map.
		`{"a":1,"b":2,"c":3,"d":4,"e":5,"f":6,"g":7,"h":8,"i":9,"j":10,"k":11,"l":12,"m":13,"n":14,"o":15,"p":16,"q":17,"a":0}`,
		`{"a":1,"b":2,"c":3,"d":4,"e":5,"f":6,"g":7,"h":8,"i":9,"j":10,"k":11,"l":12,"m":13,"n":14,"o":15,"p":16,"q":{"r":1,"r":2}}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if !json.Valid(data) {
			return
		}
		ref, refFound := referenceDuplicateKey(data)
		key, found := DuplicateKey(data)
		if found != refFound || key != ref {
			t.Fatalf("%q: got (%q, %v), reference (%q, %v)", data, key, found, ref, refFound)
		}
	})
}

// referenceDuplicateKey walks data token by token with encoding/json's own
// decoder and reports the first key repeated within an object.
func referenceDuplicateKey(data []byte) (string, bool) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var walk func() (string, bool)
	walk = func() (string, bool) {
		tok, err := dec.Token()
		if err != nil {
			return "", false
		}
		switch tok {
		case json.Delim('{'):
			seen := map[string]bool{}
			for dec.More() {
				kt, _ := dec.Token()
				k := kt.(string)
				if seen[k] {
					return k, true
				}
				seen[k] = true
				if k, dup := walk(); dup {
					return k, true
				}
			}
			_, _ = dec.Token()
		case json.Delim('['):
			for dec.More() {
				if k, dup := walk(); dup {
					return k, true
				}
			}
			_, _ = dec.Token()
		}
		return "", false
	}
	return walk()
}

func benchBody(size int) []byte {
	var b bytes.Buffer
	b.WriteByte('[')
	for i := 0; b.Len() < size; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"id":%d,"name":"item %d","owner":{"email":"user%d@example.com","roles":["read","write"]},"tags":{"env":"prod","tier":"gold"},"active":true}`, i, i, i)
	}
	b.WriteByte(']')
	return b.Bytes()
}

func BenchmarkDuplicateKey(b *testing.B) {
	for _, size := range []int{1 << 10, 64 << 10, 1 << 20} {
		body := benchBody(size)
		b.Run(fmt.Sprintf("scan/%dKB", size>>10), func(b *testing.B) {
			b.SetBytes(int64(len(body)))
			b.ReportAllocs()
			for b.Loop() {
				_, _ = DuplicateKey(body)
			}
		})
		// What core already pays to read the same body, for scale.
		b.Run(fmt.Sprintf("unmarshal/%dKB", size>>10), func(b *testing.B) {
			b.SetBytes(int64(len(body)))
			b.ReportAllocs()
			for b.Loop() {
				var v any
				_ = json.Unmarshal(body, &v)
			}
		})
	}
}
