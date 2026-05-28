package gitlab

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

func TestExtractToken(t *testing.T) {
	t.Run("PRIVATE-TOKEN wins over everything", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/gitlab/gateway/api/v4/user", nil)
		r.Header.Set("PRIVATE-TOKEN", "private-token-value")
		r.Header.Set("Authorization", "Bearer bearer-token")
		r.Header.Set("X-Warden-Token", "warden-token")
		assert.Equal(t, "private-token-value", extractToken(r))
	})

	t.Run("Bearer wins over X-Warden-Token and Basic password", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/gitlab/gateway/api/v4/user", nil)
		r.Header.Set("Authorization", "Bearer bearer-token")
		r.Header.Set("X-Warden-Token", "warden-token")
		assert.Equal(t, "bearer-token", extractToken(r))
	})

	t.Run("X-Warden-Token wins over Basic password", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/gitlab/gateway/api/v4/user", nil)
		r.Header.Set("X-Warden-Token", "warden-token")
		r.SetBasicAuth("role-name", "basic-password")
		// SetBasicAuth writes Authorization: Basic ...; extractToken sees
		// no Bearer, then checks X-Warden-Token before falling through to
		// Basic.
		assert.Equal(t, "warden-token", extractToken(r))
	})

	t.Run("Basic password returned without cert and without higher-precedence headers", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/gitlab/gateway/group/repo.git/info/refs", nil)
		r.SetBasicAuth("role-name", "jwt-as-password")
		assert.Equal(t, "jwt-as-password", extractToken(r))
	})

	t.Run("Basic password skipped when X-SSL-Client-Cert set", func(t *testing.T) {
		// Cert-auth case: Git protocol forces a placeholder password slot,
		// but the cert is the real credential.
		r := httptest.NewRequest("GET", "/v1/gitlab/gateway/group/repo.git/info/refs", nil)
		r.SetBasicAuth("role-name", "placeholder")
		r.Header.Set("X-SSL-Client-Cert", "<pem>")
		assert.Empty(t, extractToken(r))
	})

	t.Run("empty Basic password → empty (no token extracted)", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/gitlab/gateway/group/repo.git/info/refs", nil)
		r.SetBasicAuth("role-name", "")
		assert.Empty(t, extractToken(r))
	})

	t.Run("no auth → empty", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/gitlab/gateway/api/v4/user", nil)
		assert.Empty(t, extractToken(r))
	})
}

// TestSpec_ResolveUpstream covers the GitLab dispatch surface through the
// public Spec interface — confirms gitHooks is wired with identity URL
// derivation and the GitLab credential type. SDK-level behaviour (suffix
// detection, body-size defaults, credential format) is exercised directly
// in provider/sdk/githttp.
func TestSpec_ResolveUpstream(t *testing.T) {
	t.Run("git path → identity-derived upstream with overridden body cap", func(t *testing.T) {
		state := map[string]any{"git_max_body_size": int64(3 * 1024 * 1024 * 1024)}
		r := httptest.NewRequest("POST", "/v1/gitlab/gateway/group/repo.git/git-upload-pack", nil)
		d, ok := Spec.ResolveUpstream(r, "https://gitlab.com", state)
		require.True(t, ok)
		assert.Equal(t, "https://gitlab.com", d.UpstreamURL)
		assert.NotNil(t, d.ExtractCredentials)
		assert.True(t, d.SkipDefaultAccept)
		assert.True(t, d.SkipDynamicHeaders)
		assert.True(t, d.BypassBodyParsing)
		assert.Equal(t, int64(3*1024*1024*1024), d.MaxBodySize)
	})

	t.Run("git path with empty state uses default cap from SDK", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/v1/gitlab/gateway/group/repo.git/git-receive-pack", nil)
		d, ok := Spec.ResolveUpstream(r, "https://gitlab.com", map[string]any{})
		require.True(t, ok)
		assert.Equal(t, githttp.DefaultMaxBodySize, d.MaxBodySize)
	})

	t.Run("self-hosted host: REST URL = Git URL (identity derivation)", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/gitlab/gateway/group/repo.git/info/refs", nil)
		d, ok := Spec.ResolveUpstream(r, "https://gitlab.example.com", map[string]any{})
		require.True(t, ok)
		assert.Equal(t, "https://gitlab.example.com", d.UpstreamURL)
	})

	t.Run("REST path → ok=false, spec defaults apply", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/gitlab/gateway/api/v4/projects", nil)
		d, ok := Spec.ResolveUpstream(r, "https://gitlab.com", map[string]any{})
		assert.False(t, ok)
		assert.Equal(t, httpproxy.Dispatch{}, d)
	})
}

// TestSpec_DispatchExtractorRoundTrip verifies the credential extractor
// returned by Spec.ResolveUpstream produces "Basic oauth2:<token>" —
// proving the GitLab-specific BasicAuthUsername is wired through the SDK
// closure.
func TestSpec_DispatchExtractorRoundTrip(t *testing.T) {
	r := httptest.NewRequest("POST", "/v1/gitlab/gateway/group/repo.git/git-upload-pack", nil)
	d, ok := Spec.ResolveUpstream(r, "https://gitlab.com", map[string]any{})
	require.True(t, ok)

	headers, err := d.ExtractCredentials(&logical.Request{
		Credential: &credential.Credential{
			Type: credential.TypeGitLabAccessToken,
			Data: map[string]string{"access_token": "glpat_test"},
		},
	})
	require.NoError(t, err)

	auth := headers["Authorization"]
	require.True(t, len(auth) > 6 && auth[:6] == "Basic ", "expected Basic auth, got %q", auth)
	decoded, err := base64.StdEncoding.DecodeString(auth[6:])
	require.NoError(t, err)
	assert.Equal(t, "oauth2:glpat_test", string(decoded))
}

func TestSpec_DispatchExtractor_NilCredentialRejected(t *testing.T) {
	r := httptest.NewRequest("POST", "/v1/gitlab/gateway/group/repo.git/git-upload-pack", nil)
	d, ok := Spec.ResolveUpstream(r, "https://gitlab.com", map[string]any{})
	require.True(t, ok)
	_, err := d.ExtractCredentials(&logical.Request{})
	assert.ErrorContains(t, err, "no credential available")
}

func TestSpec_DispatchExtractor_WrongTypeRejected(t *testing.T) {
	r := httptest.NewRequest("POST", "/v1/gitlab/gateway/group/repo.git/git-upload-pack", nil)
	d, ok := Spec.ResolveUpstream(r, "https://gitlab.com", map[string]any{})
	require.True(t, ok)
	_, err := d.ExtractCredentials(&logical.Request{
		Credential: &credential.Credential{Type: credential.TypeGitHubToken},
	})
	assert.ErrorContains(t, err, "unsupported credential type")
}

func TestSpec_GetAuthRoleFromRequest(t *testing.T) {
	t.Run("git path with Basic Auth user → returns role", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/gitlab/gateway/group/repo.git/info/refs", nil)
		r.SetBasicAuth("contributor", "jwt-or-placeholder")
		assert.Equal(t, "contributor", Spec.GetAuthRoleFromRequest(r))
	})

	t.Run("REST path with Basic Auth user → empty (username not consumed for REST)", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/gitlab/gateway/api/v4/user", nil)
		r.SetBasicAuth("contributor", "jwt")
		assert.Empty(t, Spec.GetAuthRoleFromRequest(r))
	})
}

func TestSpec_IsUnauthenticatedRequest(t *testing.T) {
	t.Run("git probe without Authorization → true", func(t *testing.T) {
		p := "gateway/group/repo.git/info/refs"
		assert.True(t, Spec.IsUnauthenticatedRequest(httptest.NewRequest("GET", "/"+p, nil), p))
	})

	t.Run("git path with Basic Authorization → false (retry, not probe)", func(t *testing.T) {
		p := "gateway/group/repo.git/info/refs"
		r := httptest.NewRequest("GET", "/"+p, nil)
		r.SetBasicAuth("role", "jwt")
		assert.False(t, Spec.IsUnauthenticatedRequest(r, p))
	})

	t.Run("REST path → false", func(t *testing.T) {
		p := "gateway/api/v4/projects"
		assert.False(t, Spec.IsUnauthenticatedRequest(httptest.NewRequest("GET", "/"+p, nil), p))
	})
}

// TestSpec_WiringSanity asserts the spec carries the three git hooks and
// that the dispatch is opt-in (REST paths return ok=false).
func TestSpec_WiringSanity(t *testing.T) {
	assert.NotNil(t, Spec.ResolveUpstream, "Spec.ResolveUpstream must be set so git smart-HTTP can dispatch")
	assert.NotNil(t, Spec.GetAuthRoleFromRequest, "Spec.GetAuthRoleFromRequest must be set so Basic Auth user becomes role")
	assert.NotNil(t, Spec.IsUnauthenticatedRequest, "Spec.IsUnauthenticatedRequest must be set so the first Git smart-HTTP probe bypasses auth")

	r := httptest.NewRequest("GET", "/v1/gitlab/gateway/api/v4/user", nil)
	_, ok := Spec.ResolveUpstream(r, "https://gitlab.com", map[string]any{})
	assert.False(t, ok, "REST path must NOT trigger the git dispatch")

	var _ *httpproxy.ProviderSpec = Spec
}
