package roles

import (
	"reflect"
	"sort"
	"testing"
)

func TestProjectRoles_DiscoveryFieldsOnlyWhenSet(t *testing.T) {
	in := []any{
		map[string]any{
			"auth_path":     "jwt/",
			"name":          "repo-creator",
			"provider_path": "github/",
			"skill":         "gh-repo-creator",
		},
		map[string]any{"auth_path": "jwt/", "name": "plain"},
	}
	got := projectRoles(in, "")
	if len(got) != 2 {
		t.Fatalf("expected 2 roles; got %d", len(got))
	}
	if got[0]["provider_path"] != "github/" || got[0]["skill"] != "gh-repo-creator" {
		t.Errorf("discovery fields not carried: %#v", got[0])
	}
	if _, ok := got[1]["provider_path"]; ok {
		t.Errorf("provider_path present on a role without it: %#v", got[1])
	}
	if _, ok := got[1]["skill"]; ok {
		t.Errorf("skill present on a role without it: %#v", got[1])
	}
}

func TestProjectRoles_PreservesAllFields(t *testing.T) {
	in := []any{
		map[string]any{
			"auth_path":   "auth/jwt/",
			"name":        "aws-user",
			"description": "Read-only AWS access",
		},
	}
	got := projectRoles(in, "")
	if len(got) != 1 {
		t.Fatalf("expected 1 role; got %d", len(got))
	}
	want := map[string]any{
		"name":        "aws-user",
		"description": "Read-only AWS access",
		"auth_path":   "auth/jwt/",
	}
	if !reflect.DeepEqual(got[0], want) {
		t.Errorf("projectRoles() = %#v; want %#v", got[0], want)
	}
}

func TestProjectRoles_AuthPathFilter(t *testing.T) {
	in := []any{
		map[string]any{"auth_path": "auth/jwt/", "name": "aws-user"},
		map[string]any{"auth_path": "auth/jwt2/", "name": "azure-user"},
		map[string]any{"auth_path": "auth/jwt/", "name": "deployer"},
	}
	got := projectRoles(in, "auth/jwt/")
	names := make([]string, 0, len(got))
	for _, r := range got {
		names = append(names, r["name"].(string))
	}
	sort.Strings(names)
	want := []string{"aws-user", "deployer"}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("after auth-path filter: names = %v; want %v", names, want)
	}
}

func TestProjectRoles_FilterMatchesNothing(t *testing.T) {
	in := []any{
		map[string]any{"auth_path": "auth/jwt/", "name": "aws-user"},
	}
	got := projectRoles(in, "auth/cert/")
	if len(got) != 0 {
		t.Errorf("expected 0 roles; got %d", len(got))
	}
}

func TestProjectRoles_SkipsMalformedEntries(t *testing.T) {
	// The aggregator should never emit malformed entries, but the CLI
	// shouldn't panic if a future server change introduces one.
	in := []any{
		"not a map",
		nil,
		map[string]any{"auth_path": "auth/jwt/", "name": "aws-user"},
	}
	got := projectRoles(in, "")
	if len(got) != 1 || got[0]["name"] != "aws-user" {
		t.Errorf("expected 1 well-formed role; got %#v", got)
	}
}

func TestProjectRoles_DescriptionOmittedWhenAbsent(t *testing.T) {
	// Aggregator marks description with `,omitempty` server-side. When
	// missing, the projection still emits the key with a nil value so the
	// JSON renderer produces null — agents see a stable shape per record.
	in := []any{
		map[string]any{"auth_path": "auth/jwt/", "name": "aws-user"},
	}
	got := projectRoles(in, "")
	if got[0]["description"] != nil {
		t.Errorf("description = %v; want nil", got[0]["description"])
	}
}

func TestRunList_AuthPathFilterValidation(t *testing.T) {
	// Reset between cases so they don't leak.
	t.Cleanup(func() { authPathFilter = "" })

	authPathFilter = "../etc/passwd"
	err := runList(nil, nil)
	if err == nil {
		t.Fatal("expected validation error for traversal in --auth-path; got nil")
	}
}
