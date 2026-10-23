package selector_test

import (
	"encoding/json"
	"math"
	"math/rand/v2"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stephnangue/warden/auth/helper"
	"github.com/stephnangue/warden/helper/selector"
)

// Claims.Lookup is checked against helper.GetClaim, the claim resolver the
// auth methods use today: a plain name is a top-level claim, a leading '/' a
// JSON pointer, and a number comes back truncated to an integer.

func refStr(s string) selector.Scalar  { return selector.Scalar{Kind: selector.KindString, S: s} }
func refNum(n float64) selector.Scalar { return selector.Scalar{Kind: selector.KindNumber, N: n} }
func refBool(b bool) selector.Scalar   { return selector.Scalar{Kind: selector.KindBool, B: b} }
func refDeepTests() bool               { return os.Getenv("SELECTOR_DEEP_TESTS") == "1" }
func refEscapeToken(s string) string   { return strings.NewReplacer("~", "~0", "/", "~1").Replace(s) }

func refCollect(c selector.Cursor) (out []selector.Scalar) {
	for v, ok := c.Next(); ok; v, ok = c.Next() {
		out = append(out, v)
	}
	return out
}

// Keys used for objects in generated claims. Pointer tokens are drawn from the
// same set, so they hit both object members and array indexes. The empty key is
// left out: the reference reads "" as index 0, RFC 6901 does not.
var propKeys = []string{"a", "b", "0", "1", "2", "a/b", "~c", "x~1y", "https://e.x/k"}

func randValue(r *rand.Rand, depth int) any {
	k := r.IntN(8)
	if depth >= 3 {
		k = r.IntN(6)
	}
	switch k {
	case 0, 1:
		return propKeys[r.IntN(len(propKeys))]
	case 2:
		switch r.IntN(4) {
		case 0:
			return float64(r.IntN(2000) - 1000)
		case 1:
			return r.Float64()*2e6 - 1e6
		case 2:
			return math.Ldexp(1, 53) + float64(r.IntN(4))
		default:
			return 1.5
		}
	case 3:
		return r.IntN(2) == 0
	case 4:
		return nil
	case 5:
		return "s" + strconv.Itoa(r.IntN(10))
	case 6:
		arr := make([]any, r.IntN(5))
		for i := range arr {
			arr[i] = randValue(r, depth+1)
		}
		return arr
	default:
		return randObject(r, depth+1)
	}
}

func randObject(r *rand.Rand, depth int) map[string]any {
	m := make(map[string]any)
	for range r.IntN(5) {
		m[propKeys[r.IntN(len(propKeys))]] = randValue(r, depth)
	}
	return m
}

// randPointer walks v at random, sometimes stepping off it, and returns the
// pointer for the walk. Array indexes are written as RFC 6901 requires
// (decimal, no leading zero), the form both resolvers agree on.
func randPointer(r *rand.Rand, v any) string {
	var b strings.Builder
	for steps := 1 + r.IntN(4); steps > 0; steps-- {
		tok := propKeys[r.IntN(len(propKeys))]
		switch node := v.(type) {
		case map[string]any:
			if len(node) > 0 && r.IntN(4) > 0 {
				keys := make([]string, 0, len(node))
				for k := range node {
					keys = append(keys, k)
				}
				slices.Sort(keys)
				tok = keys[r.IntN(len(keys))]
			}
			v = node[tok]
		case []any:
			if len(node) > 0 && r.IntN(4) > 0 {
				tok = strconv.Itoa(r.IntN(len(node) + 1))
			}
			v = nil
			if i, err := strconv.Atoi(tok); err == nil && i < len(node) {
				v = node[i]
			}
		default:
			v = nil
		}
		b.WriteByte('/')
		b.WriteString(refEscapeToken(tok))
	}
	return b.String()
}

// compareWithReference checks Claims.Lookup against helper.GetClaim for one
// key. The reference truncates a number it returns whole, so that case compares
// the truncation.
func compareWithReference(t *testing.T, claims map[string]any, key string) {
	t.Helper()
	k, err := selector.ParseKey(key)
	if err != nil {
		t.Fatalf("ParseKey(%q): %v", key, err)
	}
	got := refCollect(selector.NewClaims(claims).Lookup(k))
	ref := helper.GetClaim(claims, key)
	var want []selector.Scalar
	switch v := ref.(type) {
	case string:
		want = []selector.Scalar{refStr(v)}
	case bool:
		want = []selector.Scalar{refBool(v)}
	case json.Number:
		if len(got) != 1 || got[0].Kind != selector.KindNumber || strconv.Itoa(int(got[0].N)) != string(v) {
			t.Fatalf("key %q: got %v; reference %v", key, got, v)
		}
		return
	case []any:
		for _, e := range v {
			switch e := e.(type) {
			case string:
				want = append(want, refStr(e))
			case float64:
				want = append(want, refNum(e))
			case bool:
				want = append(want, refBool(e))
			}
		}
	}
	if !slices.Equal(got, want) {
		t.Fatalf("key %q on %v: got %v; reference %#v", key, claims, got, ref)
	}
}

// TestClaimsLookup_MatchesReference runs 2,000 random claim sets by default and
// 20,000 with SELECTOR_DEEP_TESTS=1.
func TestClaimsLookup_MatchesReference(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	n := 2000
	if refDeepTests() {
		n = 20000
	}
	for range n {
		claims := randObject(r, 0)
		compareWithReference(t, claims, propKeys[r.IntN(len(propKeys))])
		compareWithReference(t, claims, randPointer(r, any(claims)))
	}
}
