package githttp

import (
	"encoding/base64"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/sdk/httpproxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsSmartHTTPPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/owner/repo.git/info/refs", true},
		{"/owner/repo.git/git-upload-pack", true},
		{"/owner/repo.git/git-receive-pack", true},
		{"/nested/group/repo.git/info/refs", true},
		// Non-git
		{"/repos/owner/repo", false},
		{"/user", false},
		{"/repos/owner/repo.git", false},          // no smart-HTTP suffix
		{"/repos/owner/repo.git/contents", false}, // arbitrary subpath
		{"", false},
		{"/", false},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			assert.Equal(t, tc.want, IsSmartHTTPPath(tc.path))
		})
	}
}

func TestPathAfterGateway(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"/v1/github/gateway/owner/repo.git/info/refs", "/owner/repo.git/info/refs"},
		{"/v1/github/role/foo/gateway/owner/repo.git/info/refs", "/owner/repo.git/info/refs"},
		{"/v1/github/gateway/", "/"},
		{"/v1/github/gateway", ""},
		// No /gateway segment — returned unchanged (defensive)
		{"/v1/github/something", "/v1/github/something"},
		{"", ""},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			assert.Equal(t, tc.want, pathAfterGateway(tc.in))
		})
	}
}

// hooks for tests: a GitHub-flavoured Options that the helper functions reuse.
func testHooks(t *testing.T) Hooks {
	t.Helper()
	return BuildHooks(Options{
		BasicAuthUsername: "x-access-token",
		CredentialType:    credential.TypeGitHubToken,
		TokenField:        "token",
		DeriveGitURL: func(s string) string {
			if s == "https://api.github.com" {
				return "https://github.com"
			}
			if strings.HasSuffix(s, "/api/v3") {
				return strings.TrimSuffix(s, "/api/v3")
			}
			return s
		},
	})
}

func TestBuildHooks_CredentialExtractor(t *testing.T) {
	h := testHooks(t)

	t.Run("PAT formatted as Basic with configured username", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/v1/github/gateway/owner/repo.git/git-upload-pack", nil)
		d, ok := h.ResolveUpstream(r, "https://api.github.com", map[string]any{})
		require.True(t, ok)

		headers, err := d.ExtractCredentials(&logical.Request{
			Credential: &credential.Credential{
				Type: credential.TypeGitHubToken,
				Data: map[string]string{"token": "ghp_abc123"},
			},
		})
		require.NoError(t, err)
		expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:ghp_abc123"))
		assert.Equal(t, expected, headers["Authorization"])
	})

	t.Run("nil credential rejected", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/v1/github/gateway/owner/repo.git/git-upload-pack", nil)
		d, ok := h.ResolveUpstream(r, "https://api.github.com", map[string]any{})
		require.True(t, ok)
		_, err := d.ExtractCredentials(&logical.Request{})
		assert.ErrorContains(t, err, "no credential available")
	})

	t.Run("wrong credential type rejected", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/v1/github/gateway/owner/repo.git/git-upload-pack", nil)
		d, ok := h.ResolveUpstream(r, "https://api.github.com", map[string]any{})
		require.True(t, ok)
		_, err := d.ExtractCredentials(&logical.Request{
			Credential: &credential.Credential{Type: credential.TypeAPIKey},
		})
		assert.ErrorContains(t, err, "unsupported credential type")
	})

	t.Run("missing token field rejected", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/v1/github/gateway/owner/repo.git/git-upload-pack", nil)
		d, ok := h.ResolveUpstream(r, "https://api.github.com", map[string]any{})
		require.True(t, ok)
		_, err := d.ExtractCredentials(&logical.Request{
			Credential: &credential.Credential{
				Type: credential.TypeGitHubToken,
				Data: map[string]string{},
			},
		})
		assert.ErrorContains(t, err, "credential missing token field")
	})
}

func TestBuildHooks_ResolveUpstream(t *testing.T) {
	h := testHooks(t)

	t.Run("git path → dispatch with binary-safe defaults", func(t *testing.T) {
		state := map[string]any{"git_max_body_size": int64(3 * 1024 * 1024 * 1024)}
		r := httptest.NewRequest("POST", "/v1/github/gateway/owner/repo.git/git-upload-pack", nil)
		d, ok := h.ResolveUpstream(r, "https://api.github.com", state)
		require.True(t, ok)
		assert.Equal(t, "https://github.com", d.UpstreamURL)
		assert.NotNil(t, d.ExtractCredentials)
		assert.True(t, d.SkipDefaultAccept)
		assert.True(t, d.SkipDynamicHeaders)
		assert.True(t, d.BypassBodyParsing)
		assert.Equal(t, int64(3*1024*1024*1024), d.MaxBodySize)
	})

	t.Run("empty state uses default body-size cap", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/v1/github/gateway/owner/repo.git/git-receive-pack", nil)
		d, ok := h.ResolveUpstream(r, "https://api.github.com", map[string]any{})
		require.True(t, ok)
		assert.Equal(t, DefaultMaxBodySize, d.MaxBodySize)
	})

	t.Run("REST path → ok=false, empty dispatch", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/github/gateway/repos/owner/repo", nil)
		d, ok := h.ResolveUpstream(r, "https://api.github.com", map[string]any{})
		assert.False(t, ok)
		assert.Equal(t, httpproxy.Dispatch{}, d)
	})

	t.Run("DeriveGitURL closure invoked with providerURL", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/github/gateway/org/repo.git/info/refs", nil)
		d, ok := h.ResolveUpstream(r, "https://ghe.example.com/api/v3", map[string]any{})
		require.True(t, ok)
		assert.Equal(t, "https://ghe.example.com", d.UpstreamURL)
	})
}

func TestBuildHooks_NilDeriveGitURLSubstitutesIdentity(t *testing.T) {
	h := BuildHooks(Options{
		BasicAuthUsername: "oauth2",
		CredentialType:    credential.TypeGitLabAccessToken,
		TokenField:        "access_token",
		// DeriveGitURL intentionally nil.
	})
	r := httptest.NewRequest("GET", "/v1/gitlab/gateway/group/repo.git/info/refs", nil)
	d, ok := h.ResolveUpstream(r, "https://gitlab.com", map[string]any{})
	require.True(t, ok)
	assert.Equal(t, "https://gitlab.com", d.UpstreamURL, "nil DeriveGitURL must substitute identity, not panic")
}

func TestBuildHooks_GetAuthRoleFromRequest(t *testing.T) {
	h := testHooks(t)

	t.Run("git path with Basic Auth user → returns role", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/github/gateway/owner/repo.git/info/refs", nil)
		r.SetBasicAuth("contributor", "jwt-or-placeholder")
		assert.Equal(t, "contributor", h.GetAuthRoleFromRequest(r))
	})

	t.Run("git path without Basic Auth → empty", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/github/gateway/owner/repo.git/info/refs", nil)
		assert.Empty(t, h.GetAuthRoleFromRequest(r))
	})

	t.Run("git path with empty Basic Auth user → empty", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/github/gateway/owner/repo.git/info/refs", nil)
		r.SetBasicAuth("", "jwt")
		assert.Empty(t, h.GetAuthRoleFromRequest(r))
	})

	t.Run("REST path with Basic Auth user → empty (username not consumed for REST)", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/github/gateway/user", nil)
		r.SetBasicAuth("contributor", "jwt")
		assert.Empty(t, h.GetAuthRoleFromRequest(r))
	})
}

func TestBuildHooks_IsUnauthenticatedRequest(t *testing.T) {
	h := testHooks(t)
	gitPath := "gateway/owner/repo.git/info/refs"
	roleGitPath := "role/admin/gateway/owner/repo.git/info/refs"

	t.Run("mount-relative git path without Authorization → true", func(t *testing.T) {
		assert.True(t, h.IsUnauthenticatedRequest(httptest.NewRequest("GET", "/"+gitPath, nil), gitPath))
	})
	t.Run("mount-relative role/X/gateway git path without Authorization → true", func(t *testing.T) {
		assert.True(t, h.IsUnauthenticatedRequest(httptest.NewRequest("GET", "/"+roleGitPath, nil), roleGitPath))
	})
	t.Run("git path with Basic Authorization → false", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/"+gitPath, nil)
		r.SetBasicAuth("role", "jwt")
		assert.False(t, h.IsUnauthenticatedRequest(r, gitPath))
	})
	t.Run("git path with Bearer → false", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/"+gitPath, nil)
		r.Header.Set("Authorization", "Bearer xyz")
		assert.False(t, h.IsUnauthenticatedRequest(r, gitPath))
	})
	t.Run("git path with empty Basic password → false (edge case)", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/"+gitPath, nil)
		r.SetBasicAuth("role", "")
		assert.False(t, h.IsUnauthenticatedRequest(r, gitPath))
	})
	t.Run("non-git mount-relative path → false", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/gateway/user", nil)
		assert.False(t, h.IsUnauthenticatedRequest(r, "gateway/user"))
	})
	t.Run("nil request → false", func(t *testing.T) {
		assert.False(t, h.IsUnauthenticatedRequest(nil, gitPath))
	})
	t.Run("git-upload-pack endpoint → true", func(t *testing.T) {
		p := "gateway/owner/repo.git/git-upload-pack"
		assert.True(t, h.IsUnauthenticatedRequest(httptest.NewRequest("POST", "/"+p, nil), p))
	})
	t.Run("git-receive-pack endpoint → true", func(t *testing.T) {
		p := "gateway/owner/repo.git/git-receive-pack"
		assert.True(t, h.IsUnauthenticatedRequest(httptest.NewRequest("POST", "/"+p, nil), p))
	})
	t.Run("URL-shape path also works (shape-robust)", func(t *testing.T) {
		urlPath := "/v1/github/gateway/owner/repo.git/info/refs"
		assert.True(t, h.IsUnauthenticatedRequest(httptest.NewRequest("GET", urlPath, nil), urlPath))
	})
}

// --- config helpers ---

func makeFieldData(raw map[string]interface{}) *framework.FieldData {
	return &framework.FieldData{
		Raw: raw,
		Schema: map[string]*framework.FieldSchema{
			"git_max_body_size": MaxBodySizeField(),
		},
	}
}

func TestMaxBodySizeField(t *testing.T) {
	f := MaxBodySizeField()
	assert.Equal(t, framework.TypeInt64, f.Type)
	assert.Equal(t, DefaultMaxBodySize, f.Default)
	assert.Contains(t, f.Description, "Git smart-HTTP")
}

func TestReadMaxBodySize(t *testing.T) {
	t.Run("set value returned as-is", func(t *testing.T) {
		state := map[string]any{"git_max_body_size": int64(3 * 1024 * 1024 * 1024)}
		assert.Equal(t, int64(3*1024*1024*1024), ReadMaxBodySize(state))
	})
	t.Run("missing key → default", func(t *testing.T) {
		assert.Equal(t, DefaultMaxBodySize, ReadMaxBodySize(map[string]any{}))
	})
	t.Run("zero value → default", func(t *testing.T) {
		state := map[string]any{"git_max_body_size": int64(0)}
		assert.Equal(t, DefaultMaxBodySize, ReadMaxBodySize(state))
	})
	t.Run("negative value → default", func(t *testing.T) {
		state := map[string]any{"git_max_body_size": int64(-1)}
		assert.Equal(t, DefaultMaxBodySize, ReadMaxBodySize(state))
	})
}

func TestWriteMaxBodySize(t *testing.T) {
	t.Run("valid value written to state", func(t *testing.T) {
		d := makeFieldData(map[string]interface{}{"git_max_body_size": int64(3 * 1024 * 1024 * 1024)})
		state := map[string]any{}
		require.NoError(t, WriteMaxBodySize(d, state))
		assert.Equal(t, int64(3*1024*1024*1024), state["git_max_body_size"])
	})
	t.Run("absent field is no-op", func(t *testing.T) {
		d := makeFieldData(map[string]interface{}{})
		state := map[string]any{}
		require.NoError(t, WriteMaxBodySize(d, state))
		assert.NotContains(t, state, "git_max_body_size")
	})
	t.Run("below minimum rejected", func(t *testing.T) {
		d := makeFieldData(map[string]interface{}{"git_max_body_size": int64(1024)})
		state := map[string]any{}
		err := WriteMaxBodySize(d, state)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at least")
		assert.NotContains(t, state, "git_max_body_size", "rejected write must not mutate state")
	})
	t.Run("above maximum rejected", func(t *testing.T) {
		d := makeFieldData(map[string]interface{}{"git_max_body_size": int64(20 * 1024 * 1024 * 1024)})
		state := map[string]any{}
		err := WriteMaxBodySize(d, state)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not exceed")
		assert.NotContains(t, state, "git_max_body_size")
	})
	t.Run("exact minimum accepted", func(t *testing.T) {
		d := makeFieldData(map[string]interface{}{"git_max_body_size": MinMaxBodySize})
		state := map[string]any{}
		require.NoError(t, WriteMaxBodySize(d, state))
		assert.Equal(t, MinMaxBodySize, state["git_max_body_size"])
	})
	t.Run("exact maximum accepted", func(t *testing.T) {
		d := makeFieldData(map[string]interface{}{"git_max_body_size": MaxMaxBodySize})
		state := map[string]any{}
		require.NoError(t, WriteMaxBodySize(d, state))
		assert.Equal(t, MaxMaxBodySize, state["git_max_body_size"])
	})
}

func TestInitializeMaxBodySize(t *testing.T) {
	t.Run("config value loaded into state", func(t *testing.T) {
		config := map[string]any{"git_max_body_size": int64(5 * 1024 * 1024 * 1024)}
		state := map[string]any{}
		InitializeMaxBodySize(config, state)
		assert.Equal(t, int64(5*1024*1024*1024), state["git_max_body_size"])
	})
	t.Run("missing config falls back to default", func(t *testing.T) {
		state := map[string]any{}
		InitializeMaxBodySize(map[string]any{}, state)
		assert.Equal(t, DefaultMaxBodySize, state["git_max_body_size"])
	})
}

