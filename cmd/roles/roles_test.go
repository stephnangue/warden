package roles

import (
	"net/http"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProjectRoles_DiscoveryFieldsOnlyWhenSet(t *testing.T) {
	in := []any{
		map[string]any{
			"name":          "repo-creator",
			"provider_path": "github/",
			"skill":         "gh-repo-creator",
		},
		map[string]any{"name": "plain"},
	}
	got := projectRoles(in)
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

func TestProjectRoles_NoAuthPath(t *testing.T) {
	in := []any{
		map[string]any{
			"name":        "aws-user",
			"description": "Read-only AWS access",
			"auth_path":   "jwt/", // an older server's field is not carried
		},
	}
	got := projectRoles(in)
	require.Len(t, got, 1)
	want := map[string]any{
		"name":        "aws-user",
		"description": "Read-only AWS access",
	}
	if !reflect.DeepEqual(got[0], want) {
		t.Errorf("projectRoles() = %#v; want %#v", got[0], want)
	}
}

func TestProjectRoles_SkipsMalformedEntries(t *testing.T) {
	// The server should never emit malformed entries, but the CLI shouldn't
	// panic if a future server change introduces one.
	in := []any{
		"not a map",
		nil,
		map[string]any{"name": "aws-user"},
	}
	got := projectRoles(in)
	if len(got) != 1 || got[0]["name"] != "aws-user" {
		t.Errorf("expected 1 well-formed role; got %#v", got)
	}
}

func TestProjectRoles_DescriptionOmittedWhenAbsent(t *testing.T) {
	// The server omits an empty description. The projection still emits the
	// key with a nil value so the JSON renderer produces null: agents see a
	// stable shape per record.
	got := projectRoles([]any{map[string]any{"name": "aws-user"}})
	if got[0]["description"] != nil {
		t.Errorf("description = %v; want nil", got[0]["description"])
	}
}

func TestRolesTable_NoAuthPathColumn(t *testing.T) {
	headers, rows := rolesTable(projectRoles([]any{
		map[string]any{"name": "deploy", "description": "Deploys from acme CI", "provider_path": "aws/", "skill": "aws"},
	}))
	assert.Equal(t, []string{"Name", "Description", "Provider Path", "Skill"}, headers)
	assert.Equal(t, [][]any{{"deploy", "Deploys from acme CI", "aws/", "aws"}}, rows)
}

func TestListCmd_NoAuthPathFlag(t *testing.T) {
	assert.Nil(t, ListCmd.Flags().Lookup("auth-path"), "-auth-path is gone")
	assert.NotContains(t, ListCmd.Long, "-auth-path")
	assert.NotContains(t, ListCmd.Long, `"auth_path"`)
	assert.NotContains(t, ListCmd.Long, "name,auth_path")
}

// The discovered roles render without auth paths, and the response's warnings
// go to stderr, leaving stdout clean JSON.
func TestRunList_Discovery(t *testing.T) {
	f, stdout, stderr := setupFake(t, http.StatusOK, `{"data":{
		"roles":[
			{"name":"deploy","description":"Deploys from acme CI","provider_path":"aws/","skill":"aws"},
			{"name":"recipe","skill":"gh-repo-creator"}
		],
		"warnings":["mount \"k8s/\": TokenReview unreachable"]
	}}`)

	require.NoError(t, runList(nil, nil))
	assert.Equal(t, "/v1/sys/introspect/roles", f.last(t).path)
	assert.JSONEq(t, `[
		{"name":"deploy","description":"Deploys from acme CI","provider_path":"aws/","skill":"aws"},
		{"name":"recipe","description":null,"skill":"gh-repo-creator"}
	]`, stdout.String())
	assert.Equal(t, "warning: mount \"k8s/\": TokenReview unreachable\n", stderr.String())
}
