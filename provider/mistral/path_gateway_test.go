package mistral

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildTargetURL(t *testing.T) {
	b := &mistralBackend{
		mistralURL: "https://api.mistral.ai",
	}

	tests := []struct {
		name     string
		path     string
		query    string
		expected string
		wantErr  bool
	}{
		{
			name:     "chat completions",
			path:     "/mistral/gateway/v1/chat/completions",
			expected: "https://api.mistral.ai/v1/chat/completions",
		},
		{
			name:     "embeddings",
			path:     "/mistral/gateway/v1/embeddings",
			expected: "https://api.mistral.ai/v1/embeddings",
		},
		{
			name:     "models",
			path:     "/mistral/gateway/v1/models",
			expected: "https://api.mistral.ai/v1/models",
		},
		{
			name:     "path with query",
			path:     "/mistral/gateway/v1/models",
			query:    "page=1&per_page=10",
			expected: "https://api.mistral.ai/v1/models?page=1&per_page=10",
		},
		{
			name:     "bare gateway",
			path:     "/mistral/gateway",
			expected: "https://api.mistral.ai/",
		},
		{
			name:     "gateway with trailing slash",
			path:     "/mistral/gateway/",
			expected: "https://api.mistral.ai/",
		},
		{
			name:    "no gateway marker",
			path:    "/mistral/v1/chat/completions",
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

func TestBuildTargetURL_CustomURL(t *testing.T) {
	b := &mistralBackend{
		mistralURL: "https://mistral.example.com",
	}

	result, err := b.buildTargetURL("/custom/gateway/v1/chat/completions", "")
	assert.NoError(t, err)
	assert.Equal(t, "https://mistral.example.com/v1/chat/completions", result)
}

func TestPrepareHeaders(t *testing.T) {
	b := &mistralBackend{}

	t.Run("removes security headers and injects API key", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "https://api.mistral.ai/v1/chat/completions", nil)
		req.Header.Set("Authorization", "Bearer warden-token")
		req.Header.Set("X-Warden-Token", "warden-token")
		req.Header.Set("X-Custom", "keep-me")

		b.prepareHeaders(req, "sk-test-key")

		assert.Equal(t, "Bearer sk-test-key", req.Header.Get("Authorization"))
		assert.Equal(t, "", req.Header.Get("X-Warden-Token"))
		assert.Equal(t, "keep-me", req.Header.Get("X-Custom"))
	})

	t.Run("injects default headers", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "https://api.mistral.ai/v1/chat/completions", nil)

		b.prepareHeaders(req, "sk-test-key")

		assert.Equal(t, "application/json", req.Header.Get("Accept"))
		assert.Equal(t, "warden-mistral-proxy", req.Header.Get("User-Agent"))
	})

	t.Run("preserves client-set Accept header", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "https://api.mistral.ai/v1/chat/completions", nil)
		req.Header.Set("Accept", "text/event-stream")

		b.prepareHeaders(req, "sk-test-key")

		assert.Equal(t, "text/event-stream", req.Header.Get("Accept"))
	})

	t.Run("removes hop-by-hop headers", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "https://api.mistral.ai/v1/chat/completions", nil)
		req.Header.Set("Connection", "keep-alive")
		req.Header.Set("Transfer-Encoding", "chunked")
		req.Header.Set("Proxy-Authorization", "Basic abc")

		b.prepareHeaders(req, "sk-test-key")

		assert.Equal(t, "", req.Header.Get("Connection"))
		assert.Equal(t, "", req.Header.Get("Transfer-Encoding"))
		assert.Equal(t, "", req.Header.Get("Proxy-Authorization"))
	})

	t.Run("removes Connection-listed headers", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "https://api.mistral.ai/v1/chat/completions", nil)
		req.Header.Set("Connection", "X-Custom-Hop")
		req.Header.Set("X-Custom-Hop", "should-be-removed")

		b.prepareHeaders(req, "sk-test-key")

		assert.Equal(t, "", req.Header.Get("X-Custom-Hop"))
	})

	t.Run("removes proxy headers", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "https://api.mistral.ai/v1/chat/completions", nil)
		req.Header.Set("X-Forwarded-For", "10.0.0.1")
		req.Header.Set("X-Real-Ip", "10.0.0.1")
		req.Header.Set("Forwarded", "for=10.0.0.1")

		b.prepareHeaders(req, "sk-test-key")

		assert.Equal(t, "", req.Header.Get("X-Forwarded-For"))
		assert.Equal(t, "", req.Header.Get("X-Real-Ip"))
		assert.Equal(t, "", req.Header.Get("Forwarded"))
	})

	t.Run("empty API key does not set Authorization", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "https://api.mistral.ai/v1/chat/completions", nil)

		b.prepareHeaders(req, "")

		assert.Equal(t, "", req.Header.Get("Authorization"))
	})
}
