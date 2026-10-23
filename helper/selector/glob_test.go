package selector

import (
	"math"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func mustGlob(t testing.TB, p string) *Glob {
	t.Helper()
	g, err := CompileGlob(p)
	if err != nil {
		t.Fatalf("CompileGlob(%q): %v", p, err)
	}
	return g
}

func TestGlob(t *testing.T) {
	cases := []struct {
		pattern, value string
		want           bool
	}{
		{"", "", true},
		{"", "a", false},
		{"abc", "abc", true},
		{"abc", "abcd", false},
		{"*", "", true},
		{"*", "deploy", true},
		{"*", "a/b", false},
		{"deploy-*", "deploy-prod", true},
		{"deploy-*", "deploy-", true},
		{"deploy-*", "deploy", false},
		{"deploy-*", "deploy-a/b", false},
		{"acme/*", "acme/web", true},
		{"acme/*", "acme/web/api", false},
		{"acme/**", "acme/web/api", true},
		{"acme/**", "acme/", true},
		{"**", "", true},
		{"**", "a/b/c", true},
		{"**/main", "refs/heads/main", true},
		{"**/main", "main", false},
		{"refs/heads/*", "refs/heads/main", true},
		{"refs/heads/*", "refs/heads/feat/x", false},
		{"refs/heads/**", "refs/heads/feat/x", true},
		{"?", "a", true},
		{"?", "", false},
		{"?", "/", false},
		{"?", "é", true},
		{"??", "é", false},
		{"a?c", "abc", true},
		{"a?c", "a/c", false},
		{"*.example.com", "api.example.com", true},
		{"*.example.com", "a.b.example.com", true}, // '.' is not a separator
		{"spiffe://corp/ns/*/sa/*", "spiffe://corp/ns/ci/sa/deployer", true},
		{"spiffe://corp/ns/*/sa/*", "spiffe://corp/ns/ci/x/sa/deployer", false},
		{"spiffe://corp/**/sa/deployer", "spiffe://corp/ns/ci/sa/deployer", true},
		{"**/x*y", "a/x/q/xzzy", true},
		{"**/a*b", "/a/x/ab", true},
		{"**/a*b", "/a/x/ac", false},
		{"*a*a*b", "aaaaaaaab", true},
		{"*a*a*b", "aaaaaaaa", false},
		{`\*`, "*", true},
		{`\*`, "a", false},
		{`a\?`, "a?", true},
		{`\\*`, `\abc`, true},
		{"[ab]", "[ab]", true}, // no character classes
		{"[ab]", "a", false},
		{"***", "a/b", true}, // a run of stars is '**'
		{"a**b", "a/x/b", true},
		{"a*/**", "abc/d/e", true},
		{"a*/**", "a/b", true},
		{"a*/**", "ab", false},
	}
	for _, tc := range cases {
		g := mustGlob(t, tc.pattern)
		if got := g.Match(tc.value); got != tc.want {
			t.Errorf("%q.Match(%q) = %v; want %v", tc.pattern, tc.value, got, tc.want)
		}
		if got := g.MatchBytes([]byte(tc.value)); got != tc.want {
			t.Errorf("%q.MatchBytes(%q) = %v; want %v", tc.pattern, tc.value, got, tc.want)
		}
		if got := globOracle(t, tc.pattern).MatchString(tc.value); got != tc.want {
			t.Errorf("the oracle disagrees with the table on %q / %q", tc.pattern, tc.value)
		}
	}
}

// The documented footgun: the trailing '/' of a mount path is a segment
// boundary, so "auth/*" does not reach it.
func TestGlob_MountFootgun(t *testing.T) {
	if mustGlob(t, "auth/*").Match("auth/kubernetes/") {
		t.Error(`"auth/*" matched "auth/kubernetes/"`)
	}
	for _, p := range []string{"auth/*/", "auth/**"} {
		if !mustGlob(t, p).Match("auth/kubernetes/") {
			t.Errorf("%q did not match auth/kubernetes/", p)
		}
	}
}

func TestCompileGlob_TrailingEscape(t *testing.T) {
	for _, p := range []string{`\`, `a*\`, `ab\\\`} {
		if _, err := CompileGlob(p); err == nil {
			t.Errorf("CompileGlob(%q) succeeded", p)
		}
	}
	if g := mustGlob(t, `a\\`); !g.Match(`a\`) || g.String() != `a\\` {
		t.Error(`a\\ does not match a\`)
	}
}

func TestIsPatternUnescape(t *testing.T) {
	cases := []struct {
		in        string
		isPattern bool
		exact     string
		err       bool
	}{
		{in: "acme/web", exact: "acme/web"},
		{in: "acme/*", isPattern: true},
		{in: "a?", isPattern: true},
		{in: `a\*`, exact: "a*"},
		{in: `a\?b`, exact: "a?b"},
		{in: `a\\*`, isPattern: true},
		{in: `a\\`, exact: `a\`},
		{in: `\a`, exact: "a"},
		{in: "[x]", exact: "[x]"},
		{in: `a\`, err: true},
	}
	for _, tc := range cases {
		if got := IsPattern(tc.in); got != tc.isPattern {
			t.Errorf("IsPattern(%q) = %v", tc.in, got)
		}
		if tc.isPattern {
			continue
		}
		got, err := Unescape(tc.in)
		if (err != nil) != tc.err || got != tc.exact {
			t.Errorf("Unescape(%q) = %q, %v", tc.in, got, err)
		}
	}
}

// globOracle translates the dialect into a regular expression: '*' is
// [^/]*, a run of two or more '*' is .*, '?' is [^/], and everything else is
// quoted.
func globOracle(t testing.TB, p string) *regexp.Regexp {
	t.Helper()
	var b, lit strings.Builder
	b.WriteString(`(?s)\A`)
	flush := func() {
		b.WriteString(regexp.QuoteMeta(lit.String()))
		lit.Reset()
	}
	for i := 0; i < len(p); i++ {
		switch c := p[i]; c {
		case '\\':
			i++
			lit.WriteByte(p[i])
		case '?':
			flush()
			b.WriteString(`[^/]`)
		case '*':
			flush()
			if i+1 < len(p) && p[i+1] == '*' {
				for i+1 < len(p) && p[i+1] == '*' {
					i++
				}
				b.WriteString(`.*`)
			} else {
				b.WriteString(`[^/]*`)
			}
		default:
			lit.WriteByte(c)
		}
	}
	flush()
	b.WriteString(`\z`)
	return regexp.MustCompile(b.String())
}

func FuzzGlob(f *testing.F) {
	seeds := [][2]string{
		{"deploy-*", "deploy-prod"},
		{"acme/**", "acme/web/api"},
		{"**/a*b", "/a/x/ab"},
		{"*a*a*b", "aaaaaaaab"},
		{"a?c", "a/c"},
		{`\*?\\`, `*x\`},
		{"*é?", "ééé"},
		{"**/x*y", "a/x/q/xzzy"},
		{"a*/**", "ab"},
		{"***?", "/x"},
	}
	for _, s := range seeds {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, pattern, value string) {
		g, err := CompileGlob(pattern)
		if err != nil {
			if err != errTrailingEscape && err != errTooManyStars {
				t.Fatalf("CompileGlob(%q): %v", pattern, err)
			}
			return
		}
		got := g.Match(value)
		if got != g.MatchBytes([]byte(value)) {
			t.Fatalf("Match and MatchBytes disagree on %q / %q", pattern, value)
		}
		// The oracle reads runes; compare only where both sides are valid UTF-8.
		if !utf8.ValidString(pattern) || !utf8.ValidString(value) {
			return
		}
		if want := globOracle(t, pattern).MatchString(value); got != want {
			t.Fatalf("%q.Match(%q) = %v; the oracle says %v", pattern, value, got, want)
		}
	})
}

func TestGlobMatch_NoAllocs(t *testing.T) {
	g := mustGlob(t, "spiffe://corp/**/sa/deploy-*")
	s := "spiffe://corp/ns/ci/team/sa/deploy-web"
	b := []byte(s)
	q := mustGlob(t, "?é?*")
	allocs := testing.AllocsPerRun(1000, func() {
		if !g.Match(s) || !g.MatchBytes(b) || !q.Match("aébc") || q.Match("aé/b") {
			panic("unexpected result")
		}
	})
	t.Logf("Glob.Match: %v allocs per run", allocs)
	if allocs != 0 {
		t.Fatalf("Glob.Match allocates %v times per run", allocs)
	}
}

// A long value with no match stays well inside a request's budget.
func TestGlobMatch_LongValue(t *testing.T) {
	long := strings.Repeat("a", 64<<10)
	cases := []struct {
		pattern, value string
	}{
		{"*a*a*a*b", long},
		{"**a*a*b", long},
		{"**/a*b", long + "/"},
		{"**a*b", long + "/"},
		{"**a*b*c", strings.Repeat("ab", 32<<10) + "/"},
		{"**a*b*c*d", strings.Repeat("abc", 20<<10) + "/x"},
		{"**a*b", strings.Repeat(long[:1024]+"/", 64)},
		{"**/a*/b*c", strings.Repeat("/a"+long[:1000]+"/b", 64)},
	}
	for _, tc := range cases {
		g := mustGlob(t, tc.pattern)
		start := time.Now()
		if g.Match(tc.value) {
			t.Fatalf("%q matched", tc.pattern)
		}
		elapsed := time.Since(start)
		t.Logf("%q on %d bytes: %v", tc.pattern, len(tc.value), elapsed)
		if elapsed > time.Second {
			t.Errorf("%q on %d bytes took %v", tc.pattern, len(tc.value), elapsed)
		}
	}
}

// TestGlob_MatchesOracle checks every short pattern and value over a small
// alphabet against the regular expression oracle, so the matcher's shortcuts
// are covered without a fuzzing run. SELECTOR_DEEP_TESTS=1 widens it to 7.1M
// pairs (about 9 s under -race).
func TestGlob_MatchesOracle(t *testing.T) {
	patterns, values := enumerate("ab/*?", 5), enumerate("ab/", 4)
	if deepTests() {
		patterns, values = enumerate("ab/*?", 6), enumerate("ab/", 5)
	}
	checked := 0
	for _, p := range patterns {
		g := mustGlob(t, p)
		re := globOracle(t, p)
		for _, v := range values {
			if got, want := g.Match(v), re.MatchString(v); got != want {
				t.Fatalf("%q.Match(%q) = %v; the oracle says %v", p, v, got, want)
			}
			checked++
		}
	}
	t.Logf("%d pattern/value pairs agree", checked)
}

func TestCompileGlob_StarCap(t *testing.T) {
	ten := strings.Repeat("a*", MaxGlobStars)
	// "a*" ten times, then anything but '*', has exactly ten single '*'.
	for _, p := range []string{ten + "b", "**" + ten + "b", ten + "b**" + ten + "b", ten + "b***" + ten + "b**"} {
		if _, err := CompileGlob(p); err != nil {
			t.Errorf("CompileGlob(%q): %v", p, err)
		}
	}
	for _, p := range []string{ten + "b*", "**" + ten + "?*", ten + "b**" + ten + "x*", `\*` + ten + "b*"} {
		_, err := CompileGlob(p)
		if err == nil || err.Error() != "at most 10 single '*' between '**'" {
			t.Errorf("CompileGlob(%q) = %v; want the star cap error", p, err)
		}
	}
	// At the cap, the matcher still agrees with the oracle.
	for _, p := range []string{"**" + ten + "b", "**/" + ten + "/b"} {
		g, re := mustGlob(t, p), globOracle(t, p)
		for _, v := range []string{
			strings.Repeat("a", 2*MaxGlobStars) + "b",
			strings.Repeat("a", 2*MaxGlobStars) + "/b",
			"x/" + strings.Repeat("a", MaxGlobStars) + "/b",
			strings.Repeat("a", 3*MaxGlobStars),
			strings.Repeat("ab/", 2*MaxGlobStars),
		} {
			if got, want := g.Match(v), re.MatchString(v); got != want {
				t.Errorf("%q.Match(%q) = %v; the oracle says %v", p, v, got, want)
			}
		}
	}
}

// worstCase is a glob at the star cap after a '**', and a long value that makes
// every restart of the block reach its stars.
var worstCase = struct {
	pattern, value string
}{"**" + strings.Repeat("a*", MaxGlobStars) + "b", strings.Repeat("a", 64<<10) + "/"}

// TestGlobMatch_WorstCaseAtCap checks that the worst case grows linearly with
// the value. It compares two sizes instead of bounding the time, because
// instrumentation (-race, -cover) slows the matcher by two orders of magnitude:
// a value four times longer takes about four times as long when linear and
// sixteen times when quadratic. Each size keeps its fastest of a few runs, so a
// scheduling pause does not skew the ratio. BenchmarkGlobMatch_WorstCaseAtCap
// measures the absolute cost.
func TestGlobMatch_WorstCaseAtCap(t *testing.T) {
	g := mustGlob(t, worstCase.pattern)
	fastest := func(v string) time.Duration {
		best := time.Duration(math.MaxInt64)
		for range 5 {
			start := time.Now()
			matched := g.Match(v)
			best = min(best, time.Since(start))
			if matched {
				t.Fatalf("%q matched %d bytes", worstCase.pattern, len(v))
			}
		}
		return best
	}
	short := fastest(strings.Repeat("a", 4<<10) + "/")
	long := fastest(strings.Repeat("a", 16<<10) + "/")
	if ratio := float64(long) / float64(max(short, time.Microsecond)); ratio > 8 {
		t.Fatalf("%d stars: 4 KiB took %v, 16 KiB took %v (x%.1f; linear is about x4)", MaxGlobStars, short, long, ratio)
	}
}

func BenchmarkGlobMatch_WorstCaseAtCap(b *testing.B) {
	g := mustGlob(b, worstCase.pattern)
	b.SetBytes(int64(len(worstCase.value)))
	for b.Loop() {
		if g.Match(worstCase.value) {
			b.Fatal("matched")
		}
	}
}

// deepTests reports whether SELECTOR_DEEP_TESTS=1 asks for the exhaustive
// versions of the oracle and property tests.
func deepTests() bool { return os.Getenv("SELECTOR_DEEP_TESTS") == "1" }

// enumerate returns every string over alphabet up to maxLen bytes long.
func enumerate(alphabet string, maxLen int) []string {
	out := []string{""}
	level := []string{""}
	for range maxLen {
		var next []string
		for _, s := range level {
			for i := 0; i < len(alphabet); i++ {
				next = append(next, s+alphabet[i:i+1])
			}
		}
		out = append(out, next...)
		level = next
	}
	return out
}
