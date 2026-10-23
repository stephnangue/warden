package selector

import (
	"slices"
	"strings"
	"testing"
)

func TestParseKey(t *testing.T) {
	cases := []struct {
		in   string
		name string
		path []string
	}{
		{in: "sub", name: "sub"},
		{in: "https://example.com/env", name: "https://example.com/env"},
		{in: "a~1b", name: "a~1b"}, // escapes mean nothing outside a pointer
		{in: "/", name: "/", path: []string{""}},
		{in: "/deployment/env", name: "/deployment/env", path: []string{"deployment", "env"}},
		{in: "/a~1b/~0c", name: "/a~1b/~0c", path: []string{"a/b", "~c"}},
		{in: "/~01", name: "/~01", path: []string{"~1"}},
		{in: "/groups/0", name: "/groups/0", path: []string{"groups", "0"}},
		{in: "/a//b", name: "/a//b", path: []string{"a", "", "b"}},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			k, err := ParseKey(tc.in)
			if err != nil {
				t.Fatalf("ParseKey(%q): %v", tc.in, err)
			}
			if k.Name != tc.name || !slices.Equal(k.Path, tc.path) {
				t.Fatalf("ParseKey(%q) = %q %q; want %q %q", tc.in, k.Name, k.Path, tc.name, tc.path)
			}
			if k.IsPointer() != (tc.path != nil) {
				t.Fatalf("IsPointer = %v", k.IsPointer())
			}
		})
	}
}

func TestParseKey_Refused(t *testing.T) {
	for _, in := range []string{"", "/a~", "/a~2", "/~/b", "/a/~x"} {
		if _, err := ParseKey(in); err == nil {
			t.Errorf("ParseKey(%q) succeeded; want an error", in)
		}
	}
}

func TestValidateName(t *testing.T) {
	for _, ok := range []string{"repo", "a", "service_account_name", "k8s.io/ns", "spiffe:id", "a-b", "x/", strings.Repeat("a", MaxNameLen)} {
		if err := ValidateName(ok); err != nil {
			t.Errorf("ValidateName(%q): %v", ok, err)
		}
	}
	for _, bad := range []string{"", "/repo", "Repo", "a b", "a*", "é", "a\x00", strings.Repeat("a", MaxNameLen+1)} {
		if err := ValidateName(bad); err == nil {
			t.Errorf("ValidateName(%q) succeeded; want an error", bad)
		}
	}
}
