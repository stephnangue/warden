package github

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildTargetURL(t *testing.T) {
	b := &githubBackend{
		githubURL: "https://api.github.com",
	}

	tests := []struct {
		name     string
		path     string
		query    string
		expected string
		wantErr  bool
	}{
		{
			name:     "simple path",
			path:     "/github/gateway/repos/owner/repo",
			expected: "https://api.github.com/repos/owner/repo",
		},
		{
			name:     "path with query",
			path:     "/github/gateway/repos/owner/repo/issues",
			query:    "state=open&per_page=10",
			expected: "https://api.github.com/repos/owner/repo/issues?state=open&per_page=10",
		},
		{
			name:     "bare gateway",
			path:     "/github/gateway",
			expected: "https://api.github.com/",
		},
		{
			name:     "gateway with trailing slash",
			path:     "/github/gateway/",
			expected: "https://api.github.com/",
		},
		{
			name:     "user endpoint",
			path:     "/github/gateway/user",
			expected: "https://api.github.com/user",
		},
		{
			name:    "no gateway marker",
			path:    "/github/repos/owner/repo",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := b.buildTargetURL(tc.path, tc.query)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func TestBuildTargetURL_GHE(t *testing.T) {
	b := &githubBackend{
		githubURL: "https://github.example.com/api/v3",
	}

	result, err := b.buildTargetURL("/ghe/gateway/repos/owner/repo", "")
	assert.NoError(t, err)
	assert.Equal(t, "https://github.example.com/api/v3/repos/owner/repo", result)
}

func TestPrepareHeaders(t *testing.T) {
	b := &githubBackend{
		apiVersion: "2022-11-28",
	}

	t.Run("removes security headers and injects token", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
		req.Header.Set("Authorization", "Bearer warden-token")
		req.Header.Set("X-Warden-Token", "warden-token")
		req.Header.Set("X-Custom", "keep-me")

		b.prepareHeaders(req, "ghp_test123")

		assert.Equal(t, "token ghp_test123", req.Header.Get("Authorization"))
		assert.Equal(t, "", req.Header.Get("X-Warden-Token"))
		assert.Equal(t, "keep-me", req.Header.Get("X-Custom"))
	})

	t.Run("injects GitHub-specific headers", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)

		b.prepareHeaders(req, "ghp_test123")

		assert.Equal(t, "2022-11-28", req.Header.Get("X-GitHub-Api-Version"))
		assert.Equal(t, "application/vnd.github+json", req.Header.Get("Accept"))
		assert.Equal(t, "warden-github-proxy", req.Header.Get("User-Agent"))
	})

	t.Run("preserves client-set Accept header", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
		req.Header.Set("Accept", "application/json")

		b.prepareHeaders(req, "ghp_test123")

		assert.Equal(t, "application/json", req.Header.Get("Accept"))
	})

	t.Run("preserves client-set API version", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
		req.Header.Set("X-GitHub-Api-Version", "2023-11-28")

		b.prepareHeaders(req, "ghp_test123")

		assert.Equal(t, "2023-11-28", req.Header.Get("X-GitHub-Api-Version"))
	})

	t.Run("removes hop-by-hop headers", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
		req.Header.Set("Connection", "keep-alive")
		req.Header.Set("Transfer-Encoding", "chunked")
		req.Header.Set("Proxy-Authorization", "Basic abc")

		b.prepareHeaders(req, "ghp_test123")

		assert.Equal(t, "", req.Header.Get("Connection"))
		assert.Equal(t, "", req.Header.Get("Transfer-Encoding"))
		assert.Equal(t, "", req.Header.Get("Proxy-Authorization"))
	})

	t.Run("removes Connection-listed headers", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
		req.Header.Set("Connection", "X-Custom-Hop")
		req.Header.Set("X-Custom-Hop", "should-be-removed")

		b.prepareHeaders(req, "ghp_test123")

		assert.Equal(t, "", req.Header.Get("X-Custom-Hop"))
	})

	t.Run("removes proxy headers", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
		req.Header.Set("X-Forwarded-For", "10.0.0.1")
		req.Header.Set("X-Real-Ip", "10.0.0.1")
		req.Header.Set("Forwarded", "for=10.0.0.1")

		b.prepareHeaders(req, "ghp_test123")

		assert.Equal(t, "", req.Header.Get("X-Forwarded-For"))
		assert.Equal(t, "", req.Header.Get("X-Real-Ip"))
		assert.Equal(t, "", req.Header.Get("Forwarded"))
	})

	t.Run("empty token does not set Authorization", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)

		b.prepareHeaders(req, "")

		assert.Equal(t, "", req.Header.Get("Authorization"))
	})
}
