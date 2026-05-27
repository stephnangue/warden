package github

import (
	"encoding/base64"
	"net/http/httptest"
	"testing"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/sdk/httpproxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsGitSmartHTTPPath(t *testing.T) {
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
		{"/repos/owner/repo.git/contents", false}, // GitHub REST resource, not smart-HTTP
		{"", false},
		{"/", false},
		// Query strings on info/refs are valid (e.g. ?service=git-upload-pack);
		// suffix match still holds because the query is not part of the URL path.
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			assert.Equal(t, tc.want, isGitSmartHTTPPath(tc.path))
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

func TestDeriveGitURL(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"https://api.github.com", "https://github.com"},
		{"https://api.github.com/", "https://github.com"},
		{"http://api.github.com", "http://github.com"},
		{"https://ghe.example.com/api/v3", "https://ghe.example.com"},
		{"https://ghe.example.com/api/v3/", "https://ghe.example.com"},
		// Non-matching GHE host — input is returned (trailing slash stripped).
		// Operators with non-standard layouts can set git_url explicitly.
		{"https://example.com", "https://example.com"},
		{"https://example.com/", "https://example.com"},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			assert.Equal(t, tc.want, deriveGitURL(tc.in))
		})
	}
}

func TestGitCredentialExtractor(t *testing.T) {
	t.Run("PAT formatted as Basic x-access-token", func(t *testing.T) {
		headers, err := gitCredentialExtractor(&logical.Request{
			Credential: &credential.Credential{
				Type: credential.TypeGitHubToken,
				Data: map[string]string{"token": "ghp_abc123"},
			},
		})
		require.NoError(t, err)
		expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:ghp_abc123"))
		assert.Equal(t, expected, headers["Authorization"])
	})

	t.Run("App installation token uses same shape", func(t *testing.T) {
		headers, err := gitCredentialExtractor(&logical.Request{
			Credential: &credential.Credential{
				Type: credential.TypeGitHubToken,
				Data: map[string]string{"token": "ghs_install_xyz"},
			},
		})
		require.NoError(t, err)
		expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:ghs_install_xyz"))
		assert.Equal(t, expected, headers["Authorization"])
	})

	t.Run("nil credential rejected", func(t *testing.T) {
		_, err := gitCredentialExtractor(&logical.Request{})
		assert.ErrorContains(t, err, "no credential")
	})

	t.Run("wrong credential type rejected", func(t *testing.T) {
		_, err := gitCredentialExtractor(&logical.Request{
			Credential: &credential.Credential{Type: credential.TypeAPIKey},
		})
		assert.ErrorContains(t, err, "unsupported credential type")
	})

	t.Run("missing token field rejected", func(t *testing.T) {
		_, err := gitCredentialExtractor(&logical.Request{
			Credential: &credential.Credential{
				Type: credential.TypeGitHubToken,
				Data: map[string]string{},
			},
		})
		assert.ErrorContains(t, err, "missing token")
	})
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

func TestRoleFromBasicAuthUser(t *testing.T) {
	t.Run("git path with Basic Auth user → returns role", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/github/gateway/owner/repo.git/info/refs", nil)
		r.SetBasicAuth("contributor", "jwt-or-placeholder")
		assert.Equal(t, "contributor", roleFromBasicAuthUser(r))
	})

	t.Run("git path without Basic Auth → empty (caller falls back to default_role)", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/github/gateway/owner/repo.git/info/refs", nil)
		assert.Empty(t, roleFromBasicAuthUser(r))
	})

	t.Run("git path with empty Basic Auth user → empty (caller falls back to default_role)", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/github/gateway/owner/repo.git/info/refs", nil)
		r.SetBasicAuth("", "jwt")
		assert.Empty(t, roleFromBasicAuthUser(r))
	})

	t.Run("REST path with Basic Auth user → username NOT consumed", func(t *testing.T) {
		// Username must not leak into REST role resolution. Existing REST
		// callers using Basic Auth (unusual but possible) keep current
		// behaviour.
		r := httptest.NewRequest("GET", "/v1/github/gateway/user", nil)
		r.SetBasicAuth("contributor", "jwt")
		assert.Empty(t, roleFromBasicAuthUser(r))
	})
}

func TestIsUnauthenticatedGitProbe(t *testing.T) {
	// Production callers pass mount-relative paths.
	gitPath := "gateway/owner/repo.git/info/refs"
	roleGitPath := "role/admin/gateway/owner/repo.git/info/refs"

	t.Run("mount-relative git path without Authorization → true", func(t *testing.T) {
		assert.True(t, isUnauthenticatedGitProbe(httptest.NewRequest("GET", "/"+gitPath, nil), gitPath))
	})
	t.Run("mount-relative role/X/gateway git path without Authorization → true", func(t *testing.T) {
		assert.True(t, isUnauthenticatedGitProbe(httptest.NewRequest("GET", "/"+roleGitPath, nil), roleGitPath))
	})
	t.Run("git path with Basic Authorization → false (retry, not probe)", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/"+gitPath, nil)
		r.SetBasicAuth("role", "jwt")
		assert.False(t, isUnauthenticatedGitProbe(r, gitPath))
	})
	t.Run("git path with Bearer → false", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/"+gitPath, nil)
		r.Header.Set("Authorization", "Bearer xyz")
		assert.False(t, isUnauthenticatedGitProbe(r, gitPath))
	})
	t.Run("git path with empty Basic password → false (edge case)", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/"+gitPath, nil)
		r.SetBasicAuth("role", "") // extractToken returns "" yet Authorization is set
		assert.False(t, isUnauthenticatedGitProbe(r, gitPath))
	})
	t.Run("non-git mount-relative path → false", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/gateway/user", nil)
		assert.False(t, isUnauthenticatedGitProbe(r, "gateway/user"))
	})
	t.Run("nil request → false", func(t *testing.T) {
		assert.False(t, isUnauthenticatedGitProbe(nil, gitPath))
	})
	t.Run("git-upload-pack endpoint → true", func(t *testing.T) {
		p := "gateway/owner/repo.git/git-upload-pack"
		assert.True(t, isUnauthenticatedGitProbe(httptest.NewRequest("POST", "/"+p, nil), p))
	})
	t.Run("git-receive-pack endpoint → true", func(t *testing.T) {
		p := "gateway/owner/repo.git/git-receive-pack"
		assert.True(t, isUnauthenticatedGitProbe(httptest.NewRequest("POST", "/"+p, nil), p))
	})
	t.Run("URL-shape path also works (shape-robust)", func(t *testing.T) {
		// Not how callers invoke us, but the helper must not regress if a future
		// caller passes a URL-shaped path. Documents the suffix check's robustness.
		urlPath := "/v1/github/gateway/owner/repo.git/info/refs"
		assert.True(t, isUnauthenticatedGitProbe(httptest.NewRequest("GET", urlPath, nil), urlPath))
	})
}

func TestResolveGitUpstream(t *testing.T) {
	state := map[string]any{
		"git_max_body_size": int64(3 * 1024 * 1024 * 1024), // 3 GiB
	}

	t.Run("git path → dispatch routes to git host with binary-safe defaults", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/v1/github/gateway/owner/repo.git/git-upload-pack", nil)
		d, ok := resolveGitUpstream(r, "https://api.github.com", state)
		require.True(t, ok)
		assert.Equal(t, "https://github.com", d.UpstreamURL)
		assert.NotNil(t, d.ExtractCredentials)
		assert.True(t, d.SkipDefaultAccept)
		assert.True(t, d.SkipDynamicHeaders)
		assert.True(t, d.BypassBodyParsing)
		assert.Equal(t, int64(3*1024*1024*1024), d.MaxBodySize)
	})

	t.Run("git path with empty state uses default cap", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/v1/github/gateway/owner/repo.git/git-receive-pack", nil)
		d, ok := resolveGitUpstream(r, "https://api.github.com", map[string]any{})
		require.True(t, ok)
		assert.Equal(t, DefaultGitMaxBodySize, d.MaxBodySize)
	})

	t.Run("GHE host derives git URL", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/github/gateway/org/repo.git/info/refs", nil)
		d, ok := resolveGitUpstream(r, "https://ghe.example.com/api/v3", state)
		require.True(t, ok)
		assert.Equal(t, "https://ghe.example.com", d.UpstreamURL)
	})

	t.Run("REST path → ok=false, spec defaults apply", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/github/gateway/repos/owner/repo", nil)
		d, ok := resolveGitUpstream(r, "https://api.github.com", state)
		assert.False(t, ok)
		assert.Equal(t, httpproxy.Dispatch{}, d) // sanity: empty dispatch
	})
}

// gitMaxBodySizeFromState was inlined into resolveGitUpstream; the
// default-fallback behaviour is now covered by the resolveGitUpstream tests
// above (empty-state and configured-value cases).

// readGitMaxBodySize was promoted to httpproxy.ReadInt64Config; the
// coercion contract is tested in the httpproxy package.

// --- Dispatch interaction smoke test ---
//
// Verifies that ResolveUpstream returns a Dispatch whose extractor produces
// the right Basic Auth header end-to-end, and that the dispatch can be
// applied by the httpproxy SDK without panicking. Full end-to-end gateway
// behaviour is covered by the e2e_test/ suite.

func TestResolveGitUpstream_DispatchExtractorRoundTrip(t *testing.T) {
	r := httptest.NewRequest("POST", "/v1/github/gateway/owner/repo.git/git-upload-pack", nil)
	d, ok := resolveGitUpstream(r, "https://api.github.com", map[string]any{})
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

// Compile-time sanity: spec wires all three git-related hooks.
func TestSpec_WiringSanity(t *testing.T) {
	assert.NotNil(t, Spec.ResolveUpstream, "Spec.ResolveUpstream must be set so git smart-HTTP can dispatch")
	assert.NotNil(t, Spec.GetAuthRoleFromRequest, "Spec.GetAuthRoleFromRequest must be set so Basic Auth user becomes role")
	assert.NotNil(t, Spec.IsUnauthenticatedRequest, "Spec.IsUnauthenticatedRequest must be set so the first Git smart-HTTP probe bypasses auth")
	// Sanity: the dispatch returned for a non-git path must be ok=false so REST
	// callers see no behaviour change.
	r := httptest.NewRequest("GET", "/v1/github/gateway/user", nil)
	_, ok := Spec.ResolveUpstream(r, DefaultGitHubURL, map[string]any{})
	assert.False(t, ok, "REST path must NOT trigger the git dispatch")

	// httpproxy import is used in this assertion to anchor the type relationship.
	var _ *httpproxy.ProviderSpec = Spec
}
