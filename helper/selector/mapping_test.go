package selector

import (
	"slices"
	"strconv"
	"strings"
	"testing"
)

var jwtBuiltins = []string{"sub", "iss", "aud"}

func TestCompileMapping(t *testing.T) {
	m, err := CompileMapping(jwtBuiltins, map[string]string{
		"repository":      "repo",
		"/deployment/env": "env",
		"sub":             "sub", // identity mapping: publishes a built-in
		"iss":             "issuer",
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"sub": "sub", "iss": "iss", "aud": "aud",
		"repo": "repository", "env": "/deployment/env", "issuer": "iss",
	} {
		k, ok := m.Resolve(name)
		if !ok || k.Name != want {
			t.Errorf("Resolve(%q) = %q, %v; want %q", name, k.Name, ok, want)
		}
	}
	if k, _ := m.Resolve("env"); !slices.Equal(k.Path, []string{"deployment", "env"}) {
		t.Errorf("env path = %q", k.Path)
	}
	for _, name := range []string{"repository", "email", "mount", "kind", "/deployment/env"} {
		if _, ok := m.Resolve(name); ok {
			t.Errorf("Resolve(%q) answered; a mount answers only built-in and mapped names", name)
		}
	}
	if got, want := m.Names(), []string{"aud", "env", "iss", "issuer", "repo", "sub"}; !slices.Equal(got, want) {
		t.Errorf("Names() = %q; want %q", got, want)
	}
	if got, want := m.Mapped(), []string{"env", "issuer", "repo", "sub"}; !slices.Equal(got, want) {
		t.Errorf("Mapped() = %q; want %q", got, want)
	}
	// Accessors hand out the Mapping's own slices: no copy per call.
	if &m.Names()[0] != &m.Names()[0] || &m.Mapped()[0] != &m.Mapped()[0] {
		t.Error("Names() or Mapped() copies its slice")
	}
}

func TestCompileMapping_Empty(t *testing.T) {
	m, err := CompileMapping(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Names()) != 0 || len(m.Mapped()) != 0 {
		t.Fatalf("empty mapping has names %q", m.Names())
	}
	var nilMapping *Mapping
	if _, ok := nilMapping.Resolve("sub"); ok || nilMapping.Names() != nil || nilMapping.Mapped() != nil {
		t.Fatal("nil Mapping answered")
	}
}

func TestCompileMapping_Refused(t *testing.T) {
	tooMany := make(map[string]string, MaxMappingEntries+1)
	for i := range MaxMappingEntries + 1 {
		tooMany["claim"+strconv.Itoa(i)] = "fact" + strconv.Itoa(i)
	}
	cases := []struct {
		name     string
		builtins []string
		facts    map[string]string
		want     string
	}{
		{"bad target", jwtBuiltins, map[string]string{"repository": "Repo"}, "may contain only"},
		{"target starts with slash", jwtBuiltins, map[string]string{"repository": "/repo"}, `must not start with "/"`},
		{"long target", jwtBuiltins, map[string]string{"repository": strings.Repeat("r", MaxNameLen+1)}, "longer than"},
		{"mount reserved", jwtBuiltins, map[string]string{"repository": "mount"}, "reserved"},
		{"kind reserved", jwtBuiltins, map[string]string{"typ": "kind"}, "reserved"},
		{"another source's built-in", jwtBuiltins, map[string]string{"email": "sub"}, `"sub" is a built-in fact on this mount`},
		{"two sources one name", nil, map[string]string{"username": "workload", "service_account_uid": "workload"}, `fact "workload" is produced by both "service_account_uid" and "username"`},
		{"bad source pointer", jwtBuiltins, map[string]string{"/a~2": "a"}, `"~" must be followed`},
		{"empty source", jwtBuiltins, map[string]string{"": "a"}, "empty fact key"},
		{"too many", nil, tooMany, "at most 32 facts"},
		{"bad built-in", []string{"Sub"}, nil, "built-in fact"},
		{"reserved built-in", []string{"mount"}, nil, "reserved"},
		{"duplicate built-in", []string{"sub", "sub"}, nil, "listed twice"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileMapping(tc.builtins, tc.facts)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v; want one containing %q", err, tc.want)
			}
		})
	}
}

func TestCompileMapping_AtLimit(t *testing.T) {
	facts := make(map[string]string, MaxMappingEntries)
	for i := range MaxMappingEntries {
		facts["claim"+strconv.Itoa(i)] = "fact" + strconv.Itoa(i)
	}
	if _, err := CompileMapping(nil, facts); err != nil {
		t.Fatalf("%d entries refused: %v", MaxMappingEntries, err)
	}
}
