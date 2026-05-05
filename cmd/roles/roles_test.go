package roles

import (
	"reflect"
	"sort"
	"testing"
)

// projectRoles mirrors the per-record projection runRoles applies to the
// raw aggregator response. Extracted as a pure function so we can table-test
// the shape (name first, description, auth_path) without round-tripping
// through the API client.
func projectRoles(rawRoles []any, authPathFilter string) []map[string]any {
	items := make([]map[string]any, 0, len(rawRoles))
	for _, r := range rawRoles {
		rm, ok := r.(map[string]any)
		if !ok {
			continue
		}
		ap, _ := rm["auth_path"].(string)
		if authPathFilter != "" && ap != authPathFilter {
			continue
		}
		items = append(items, map[string]any{
			"name":        rm["name"],
			"description": rm["description"],
			"auth_path":   ap,
		})
	}
	return items
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

func TestRunRoles_AuthPathFilterValidation(t *testing.T) {
	// Reset between cases so they don't leak.
	t.Cleanup(func() { authPathFilter = "" })

	authPathFilter = "../etc/passwd"
	err := runRoles(nil, nil)
	if err == nil {
		t.Fatal("expected validation error for traversal in --auth-path; got nil")
	}
}
