package github

import (
	"encoding/base64"
	"net/http/httptest"
	"testing"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/sdk/githttp"
	"github.com/stephnangue/warden/provider/sdk/httpproxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeriveGitURL(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"https://api.github.com", "https://github.com"},
		{"https://api.github.com/", "https://github.com"},
		{"http://api.github.com", "http://github.com"},
		{"https://ghe.example.com/api/v3", "https://ghe.example.com"},
		{"https://ghe.example.com/api/v3/", "https://ghe.example.com"},
		// Non-matching host — input is returned (trailing slash stripped).
		{"https://example.com", "https://example.com"},
		{"https://example.com/", "https://example.com"},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			assert.Equal(t, tc.want, deriveGitURL(tc.in))
		})
	}
}

func TestExtractToken(t *testing.T) {
	t.Run("X-Warden-Token wins over Bearer and Basic", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/github/gateway/user", nil)
		r.Header.Set("X-Warden-Token", "warden-token")
		r.Header.Set("Authorization", "Bearer bearer-token")
		assert.Equal(t, "warden-token", extractToken(r))
	})

	t.Run("Bearer wins over Basic password", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/github/gateway/user", nil)
		r.Header.Set("Authorization", "Bearer bearer-token")
		r.SetBasicAuth("role-name", "basic-password")
		// SetBasicAuth overwrites Authorization, so re-set the Bearer for clarity.
		r.Header.Set("Authorization", "Bearer bearer-token")
		assert.Equal(t, "bearer-token", extractToken(r))
	})

	t.Run("Basic password returned without cert and without Bearer", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/github/gateway/owner/repo.git/info/refs", nil)
		r.SetBasicAuth("role-name", "jwt-as-password")
		assert.Equal(t, "jwt-as-password", extractToken(r))
	})

	t.Run("Basic password skipped when X-SSL-Client-Cert set", func(t *testing.T) {
		// Cert-auth case: Git protocol forces a placeholder password slot, but
		// the cert is the real credential. Reading the placeholder would hand
		// it to the JWT validator and break the flow.
		r := httptest.NewRequest("GET", "/v1/github/gateway/owner/repo.git/info/refs", nil)
		r.SetBasicAuth("role-name", "placeholder")
		r.Header.Set("X-SSL-Client-Cert", "<pem>")
		assert.Empty(t, extractToken(r))
	})

	t.Run("no auth → empty", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/github/gateway/user", nil)
		assert.Empty(t, extractToken(r))
	})
}

// TestSpec_ResolveUpstream covers the GitHub-specific dispatch surface
// through the public Spec interface — confirms gitHooks is wired with the
// GitHub deriveGitURL and credential type. The shared SDK behaviour
// (suffix detection, body-size defaults, credential format) is exercised
// directly in provider/sdk/githttp; here we only verify the GitHub
// binding produces the expected URLs and Authorization headers.
func TestSpec_ResolveUpstream(t *testing.T) {
	t.Run("git path → github.com with overridden body cap", func(t *testing.T) {
		state := map[string]any{"git_max_body_size": int64(3 * 1024 * 1024 * 1024)}
		r := httptest.NewRequest("POST", "/v1/github/gateway/owner/repo.git/git-upload-pack", nil)
		d, ok := Spec.ResolveUpstream(r, "https://api.github.com", state)
		require.True(t, ok)
		assert.Equal(t, "https://github.com", d.UpstreamURL)
		assert.NotNil(t, d.ExtractCredentials)
		assert.True(t, d.SkipDefaultAccept)
		assert.True(t, d.SkipDynamicHeaders)
		assert.True(t, d.BypassBodyParsing)
		assert.Equal(t, int64(3*1024*1024*1024), d.MaxBodySize)
	})

	t.Run("git path with empty state uses default cap from SDK", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/v1/github/gateway/owner/repo.git/git-receive-pack", nil)
		d, ok := Spec.ResolveUpstream(r, "https://api.github.com", map[string]any{})
		require.True(t, ok)
		assert.Equal(t, githttp.DefaultMaxBodySize, d.MaxBodySize)
	})

	t.Run("GHE host derives git URL", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/github/gateway/org/repo.git/info/refs", nil)
		d, ok := Spec.ResolveUpstream(r, "https://ghe.example.com/api/v3", map[string]any{})
		require.True(t, ok)
		assert.Equal(t, "https://ghe.example.com", d.UpstreamURL)
	})

	t.Run("REST path → ok=false, spec defaults apply", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/github/gateway/repos/owner/repo", nil)
		d, ok := Spec.ResolveUpstream(r, "https://api.github.com", map[string]any{})
		assert.False(t, ok)
		assert.Equal(t, httpproxy.Dispatch{}, d)
	})
}

// TestSpec_DispatchExtractorRoundTrip verifies the credential extractor
// returned by Spec.ResolveUpstream produces "Basic x-access-token:<PAT>"
// — proving the GitHub-specific BasicAuthUsername is wired through the
// SDK closure.
func TestSpec_DispatchExtractorRoundTrip(t *testing.T) {
	r := httptest.NewRequest("POST", "/v1/github/gateway/owner/repo.git/git-upload-pack", nil)
	d, ok := Spec.ResolveUpstream(r, "https://api.github.com", map[string]any{})
	require.True(t, ok)

	headers, err := d.ExtractCredentials(&logical.Request{
		Credential: &credential.Credential{
			Type: credential.TypeGitHubToken,
			Data: map[string]string{"token": "ghp_test"},
		},
	})
	require.NoError(t, err)

	auth := headers["Authorization"]
	require.True(t, len(auth) > 6 && auth[:6] == "Basic ", "expected Basic auth, got %q", auth)
	decoded, err := base64.StdEncoding.DecodeString(auth[6:])
	require.NoError(t, err)
	assert.Equal(t, "x-access-token:ghp_test", string(decoded))
}

// TestSpec_WiringSanity asserts the spec carries the three git hooks and
// that the dispatch is opt-in (REST paths return ok=false).
func TestSpec_WiringSanity(t *testing.T) {
	assert.NotNil(t, Spec.ResolveUpstream, "Spec.ResolveUpstream must be set so git smart-HTTP can dispatch")
	assert.NotNil(t, Spec.GetAuthRoleFromRequest, "Spec.GetAuthRoleFromRequest must be set so Basic Auth user becomes role")
	assert.NotNil(t, Spec.IsUnauthenticatedRequest, "Spec.IsUnauthenticatedRequest must be set so the first Git smart-HTTP probe bypasses auth")

	r := httptest.NewRequest("GET", "/v1/github/gateway/user", nil)
	_, ok := Spec.ResolveUpstream(r, DefaultGitHubURL, map[string]any{})
	assert.False(t, ok, "REST path must NOT trigger the git dispatch")

	var _ *httpproxy.ProviderSpec = Spec
}
