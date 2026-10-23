package selector

import (
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// testSource answers names the way an admission does: mount and kind directly,
// anything else through the mount's Mapping into its Facts.
type testSource struct {
	mount, kind string
	mapping     *Mapping
	facts       Facts
}

func (s *testSource) Lookup(name string) Cursor {
	switch name {
	case NameMount:
		return One(s.mount)
	case NameKind:
		return One(s.kind)
	}
	key, ok := s.mapping.Resolve(name)
	if !ok {
		return Cursor{}
	}
	return s.facts.Lookup(key)
}

func mustRule(t testing.TB, s map[string][]string) *Rule {
	t.Helper()
	r, err := Compile(s)
	if err != nil {
		t.Fatalf("Compile(%v): %v", s, err)
	}
	return r
}

func jwtSource(t testing.TB, claims string, facts map[string]string) *testSource {
	t.Helper()
	m, err := CompileMapping(jwtBuiltins, facts)
	if err != nil {
		t.Fatal(err)
	}
	return &testSource{mount: "auth/github-oidc/", kind: "agent", mapping: m, facts: NewClaims(decodeClaims(t, claims))}
}

func TestRuleMatch(t *testing.T) {
	src := jwtSource(t, `{
		"sub": "repo:acme/web:ref:refs/heads/main",
		"iss": "https://token.actions.githubusercontent.com",
		"aud": ["warden", "other"],
		"repository": "acme/web",
		"ref": "refs/heads/main",
		"run_number": 10,
		"ephemeral": true,
		"deployment": {"env": "prod"},
		"email": "dev@acme.example",
		"labels": {"team": "web"}
	}`, map[string]string{
		"repository":      "repo",
		"ref":             "ref",
		"run_number":      "run",
		"ephemeral":       "ephemeral",
		"/deployment/env": "env",
		"labels":          "labels",
	})
	cases := []struct {
		name string
		rule map[string][]string
		want bool
	}{
		{"exact", map[string][]string{"repo": {"acme/web"}}, true},
		{"glob", map[string][]string{"repo": {"acme/*"}}, true},
		{"glob misses", map[string][]string{"repo": {"other/*"}}, false},
		{"any of", map[string][]string{"repo": {"x/y", "acme/web"}}, true},
		{"and across names", map[string][]string{"repo": {"acme/*"}, "ref": {"refs/heads/main"}}, true},
		{"and fails on one name", map[string][]string{"repo": {"acme/*"}, "ref": {"refs/heads/dev"}}, false},
		{"multi-valued fact", map[string][]string{"aud": {"warden"}}, true},
		{"multi-valued, none matches", map[string][]string{"aud": {"nope"}}, false},
		{"pointer-mapped", map[string][]string{"env": {"prod"}}, true},
		{"number exact", map[string][]string{"run": {"10"}}, true},
		{"number glob is type-blind", map[string][]string{"run": {"1*"}}, true},
		{"number mismatch", map[string][]string{"run": {"1"}}, false},
		{"bool", map[string][]string{"ephemeral": {"true"}}, true},
		{"bool mismatch", map[string][]string{"ephemeral": {"false"}}, false},
		{"mount pin", map[string][]string{"mount": {"auth/github-oidc/"}, "repo": {"acme/web"}}, true},
		{"mount pin elsewhere", map[string][]string{"mount": {"auth/kubernetes/"}, "repo": {"acme/web"}}, false},
		{"mount glob footgun", map[string][]string{"mount": {"auth/*"}}, false},
		{"mount glob", map[string][]string{"mount": {"auth/*/"}}, true},
		{"kind", map[string][]string{"kind": {"agent"}}, true},
		{"kind human", map[string][]string{"kind": {"human"}}, false},
		{"absent fact fails", map[string][]string{"repo": {"acme/web"}, "nope": {"x"}}, false},
		{"unmapped claim is invisible", map[string][]string{"email": {"dev@acme.example"}}, false},
		{"non-scalar fails", map[string][]string{"labels": {"*"}}, false},
		{"escaped star is exact", map[string][]string{"repo": {`acme/\*`}}, false},
		{"built-in", map[string][]string{"iss": {"https://token.actions.githubusercontent.com"}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := mustRule(t, tc.rule).Match(src); got != tc.want {
				t.Fatalf("Match = %v; want %v", got, tc.want)
			}
		})
	}
}

func TestRuleMatch_NilAndEmpty(t *testing.T) {
	src := jwtSource(t, `{"sub":"a"}`, nil)
	var nilRule *Rule
	if nilRule.Match(src) || (&Rule{}).Match(src) {
		t.Fatal("a nil or empty rule matched")
	}
}

func TestCompile_Values(t *testing.T) {
	r := mustRule(t, map[string][]string{
		"repo": {"b", "a", "b", `\a`, "x*", "x*", "a"},
		"aud":  {"warden"},
	})
	if len(r.keys) != 2 || r.keys[0].name != "aud" || r.keys[1].name != "repo" {
		t.Fatalf("keys not sorted: %+v", r.keys)
	}
	if got := r.Names(); !slices.Equal(got, []string{"aud", "repo"}) || &got[0] != &r.Names()[0] {
		t.Fatalf("Names() = %q, or copied", got)
	}
	var nilRule *Rule
	if nilRule.Names() != nil {
		t.Fatal("nil Rule has names")
	}
	vals := r.keys[1].values
	if len(vals) != 3 || vals[0].lit != "a" || vals[1].lit != "b" || vals[2].glob == nil || vals[2].glob.String() != "x*" {
		t.Fatalf("values not collapsed to exact a, b then glob x*: %+v", vals)
	}
}

func TestCompile_Refused(t *testing.T) {
	tooManyNames := make(map[string][]string, MaxRuleNames+1)
	for i := range MaxRuleNames + 1 {
		tooManyNames["n"+strconv.Itoa(i)] = []string{"v"}
	}
	tooManyValues := make([]string, MaxRuleValues+1)
	for i := range tooManyValues {
		tooManyValues[i] = "v" + strconv.Itoa(i)
	}
	cases := []struct {
		name string
		rule map[string][]string
		want string
	}{
		{"empty rule", map[string][]string{}, "at least one fact"},
		{"nil rule", nil, "at least one fact"},
		{"no values", map[string][]string{"repo": {}}, "at least one value"},
		{"empty value", map[string][]string{"repo": {""}}, "empty value"},
		{"bad name", map[string][]string{"Repo": {"x"}}, "may contain only"},
		{"pointer name", map[string][]string{"/repo": {"x"}}, `must not start with "/"`},
		{"too many names", tooManyNames, "at most 32 facts"},
		{"too many values", map[string][]string{"repo": tooManyValues}, "at most 32 values"},
		{"long value", map[string][]string{"repo": {strings.Repeat("v", MaxValueLen+1)}}, "longer than 1024"},
		{"trailing escape, exact", map[string][]string{"repo": {`a\`}}, "escapes nothing"},
		{"trailing escape, glob", map[string][]string{"repo": {`a*\`}}, "escapes nothing"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Compile(tc.rule)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v; want one containing %q", err, tc.want)
			}
		})
	}
	atLimit := map[string][]string{"repo": tooManyValues[:MaxRuleValues], "v": {strings.Repeat("v", MaxValueLen)}}
	if _, err := Compile(atLimit); err != nil {
		t.Fatalf("a rule at the limits was refused: %v", err)
	}
}

func TestRuleMatch_NoAllocs(t *testing.T) {
	groups := make([]any, 200)
	for i := range groups {
		groups[i] = "group-" + strconv.Itoa(i)
	}
	claims := map[string]any{
		"sub":        "repo:acme/web",
		"repository": "acme/web",
		"groups":     groups,
		"run_number": 1234.0,
		"ratio":      0.25,
		"ephemeral":  true,
		"deployment": map[string]any{"env": "prod", "region": "eu-west-1"},
	}
	m, err := CompileMapping(jwtBuiltins, map[string]string{
		"repository":         "repo",
		"groups":             "groups",
		"run_number":         "run",
		"ratio":              "ratio",
		"ephemeral":          "ephemeral",
		"/deployment/env":    "env",
		"/deployment/region": "region",
	})
	if err != nil {
		t.Fatal(err)
	}
	var src Source = &testSource{mount: "auth/jwt/", kind: "agent", mapping: m, facts: NewClaims(claims)}
	rules := []*Rule{
		mustRule(t, map[string][]string{
			"mount":     {"auth/*/"},
			"kind":      {"agent"},
			"repo":      {"other/x", "acme/*"},
			"groups":    {"nope", "group-19?"}, // the matching element is near the end
			"run":       {"12*"},
			"ratio":     {"0.25"},
			"ephemeral": {"true"},
			"env":       {"prod"},
			"region":    {"eu-**"},
			"sub":       {"repo:acme/web"},
		}),
		mustRule(t, map[string][]string{"groups": {"absent-group"}}), // walks all 200 and fails
	}
	allocs := testing.AllocsPerRun(1000, func() {
		if !rules[0].Match(src) || rules[1].Match(src) {
			panic("unexpected match result")
		}
	})
	t.Logf("Rule.Match through a Source: %v allocs per run", allocs)
	if allocs != 0 {
		t.Fatalf("Rule.Match allocates %v times per run", allocs)
	}
}

func TestRuleMatch_Concurrent(t *testing.T) {
	src := jwtSource(t, `{"sub":"a","repository":"acme/web","n":3,"groups":["x","y"]}`,
		map[string]string{"repository": "repo", "n": "n", "groups": "groups"})
	match := mustRule(t, map[string][]string{"repo": {"acme/*"}, "n": {"3"}, "groups": {"y"}})
	miss := mustRule(t, map[string][]string{"repo": {"acme/*"}, "groups": {"z"}})
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 1000 {
				if !match.Match(src) || miss.Match(src) {
					t.Error("unexpected result under concurrency")
					return
				}
				src.mapping.Names()
			}
		}()
	}
	wg.Wait()
}
