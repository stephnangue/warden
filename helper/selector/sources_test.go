package selector

import (
	"encoding/json"
	"testing"
)

func TestMappingSources(t *testing.T) {
	m, err := CompileMapping(jwtBuiltins, map[string]string{
		"repository":      "repo",
		"/deployment/env": "env",
		"sub":             "sub",
	})
	if err != nil {
		t.Fatal(err)
	}
	keys := m.Sources()
	if len(keys) != len(m.Names()) {
		t.Fatalf("Sources has %d keys, Names %d", len(keys), len(m.Names()))
	}
	for i, name := range m.Names() {
		want, _ := m.Resolve(name)
		if keys[i].Name != want.Name {
			t.Errorf("Sources()[%d] = %q, want %q for %q", i, keys[i].Name, want.Name, name)
		}
	}
	env, _ := m.Resolve("env")
	if !env.IsPointer() || env.Path[0] != "deployment" {
		t.Errorf("env reads %+v", env)
	}
	if (*Mapping)(nil).Sources() != nil {
		t.Error("a nil mapping has no sources")
	}
}

// Claims encoded and decoded again answer every lookup alike, types included.
func TestClaimsEncodeJSON(t *testing.T) {
	var m map[string]any
	src := `{"s":"x","n":3,"b":true,"a":["p","q"],"o":{"k":"v"}}`
	if err := json.Unmarshal([]byte(src), &m); err != nil {
		t.Fatal(err)
	}
	out, err := NewClaims(m).EncodeJSON()
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatal(err)
	}
	a, b := NewClaims(m), NewClaims(back)
	for _, raw := range []string{"s", "n", "b", "a", "/o/k", "/a/1", "missing"} {
		k, err := ParseKey(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := render(b.Lookup(k)), render(a.Lookup(k)); got != want {
			t.Errorf("%s: %q, want %q", raw, got, want)
		}
	}
	for _, c := range []*Claims{nil, NewClaims(nil)} {
		if out, err := c.EncodeJSON(); err != nil || string(out) != "{}" {
			t.Errorf("empty claims encode as %q, %v", out, err)
		}
	}
}

func render(c Cursor) string {
	return string(AppendValues(nil, &c, ','))
}
