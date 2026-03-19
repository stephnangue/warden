package anthropic

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildTargetURL(t *testing.T) {
	b := &anthropicBackend{
		anthropicURL: "https://api.anthropic.com",
	}

	tests := []struct {
		name     string
		path     string
		query    string
		expected string
		wantErr  bool
	}{
		{
			name:     "messages",
			path:     "/anthropic/gateway/v1/messages",
			expected: "https://api.anthropic.com/v1/messages",
		},
		{
			name:     "models",
			path:     "/anthropic/gateway/v1/models",
			expected: "https://api.anthropic.com/v1/models",
		},
		{
			name:     "path with query",
			path:     "/anthropic/gateway/v1/models",
			query:    "page=1&per_page=10",
			expected: "https://api.anthropic.com/v1/models?page=1&per_page=10",
		},
		{
			name:     "bare gateway",
			path:     "/anthropic/gateway",
			expected: "https://api.anthropic.com/",
		},
		{
			name:     "gateway with trailing slash",
			path:     "/anthropic/gateway/",
			expected: "https://api.anthropic.com/",
		},
		{
			name:    "no gateway marker",
			path:    "/anthropic/v1/messages",
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
	b := &anthropicBackend{
		anthropicURL: "https://anthropic.example.com",
	}

	result, err := b.buildTargetURL("/custom/gateway/v1/messages", "")
	assert.NoError(t, err)
	assert.Equal(t, "https://anthropic.example.com/v1/messages", result)
}

func TestPrepareHeaders(t *testing.T) {
	b := &anthropicBackend{}

	t.Run("removes security headers and injects API key", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", nil)
		req.Header.Set("Authorization", "Bearer warden-token")
		req.Header.Set("X-Warden-Token", "warden-token")
		req.Header.Set("X-Custom", "keep-me")

		b.prepareHeaders(req, "sk-ant-test-key")

		assert.Equal(t, "sk-ant-test-key", req.Header.Get("x-api-key"))
		assert.Equal(t, anthropicAPIVersionHeader, req.Header.Get("anthropic-version"))
		assert.Equal(t, "", req.Header.Get("Authorization"))
		assert.Equal(t, "", req.Header.Get("X-Warden-Token"))
		assert.Equal(t, "keep-me", req.Header.Get("X-Custom"))
	})

	t.Run("injects default headers", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", nil)

		b.prepareHeaders(req, "sk-ant-test-key")

		assert.Equal(t, "application/json", req.Header.Get("Accept"))
		assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
		assert.Equal(t, "warden-anthropic-proxy", req.Header.Get("User-Agent"))
	})

	t.Run("preserves client-set Accept header", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", nil)
		req.Header.Set("Accept", "text/event-stream")

		b.prepareHeaders(req, "sk-ant-test-key")

		assert.Equal(t, "text/event-stream", req.Header.Get("Accept"))
	})

	t.Run("preserves client-set Content-Type header", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", nil)
		req.Header.Set("Content-Type", "multipart/form-data")

		b.prepareHeaders(req, "sk-ant-test-key")

		assert.Equal(t, "multipart/form-data", req.Header.Get("Content-Type"))
	})

	t.Run("removes hop-by-hop headers", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", nil)
		req.Header.Set("Connection", "keep-alive")
		req.Header.Set("Transfer-Encoding", "chunked")
		req.Header.Set("Proxy-Authorization", "Basic abc")

		b.prepareHeaders(req, "sk-ant-test-key")

		assert.Equal(t, "", req.Header.Get("Connection"))
		assert.Equal(t, "", req.Header.Get("Transfer-Encoding"))
		assert.Equal(t, "", req.Header.Get("Proxy-Authorization"))
	})

	t.Run("removes Connection-listed headers", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", nil)
		req.Header.Set("Connection", "X-Custom-Hop")
		req.Header.Set("X-Custom-Hop", "should-be-removed")

		b.prepareHeaders(req, "sk-ant-test-key")

		assert.Equal(t, "", req.Header.Get("X-Custom-Hop"))
	})

	t.Run("removes proxy headers", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", nil)
		req.Header.Set("X-Forwarded-For", "10.0.0.1")
		req.Header.Set("X-Real-Ip", "10.0.0.1")
		req.Header.Set("Forwarded", "for=10.0.0.1")

		b.prepareHeaders(req, "sk-ant-test-key")

		assert.Equal(t, "", req.Header.Get("X-Forwarded-For"))
		assert.Equal(t, "", req.Header.Get("X-Real-Ip"))
		assert.Equal(t, "", req.Header.Get("Forwarded"))
	})

	t.Run("empty API key does not set x-api-key", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", nil)

		b.prepareHeaders(req, "")

		assert.Equal(t, "", req.Header.Get("x-api-key"))
		// anthropic-version should still be set
		assert.Equal(t, anthropicAPIVersionHeader, req.Header.Get("anthropic-version"))
	})

	t.Run("removes client-sent x-api-key and anthropic-version", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", nil)
		req.Header.Set("x-api-key", "spoofed-key")
		req.Header.Set("anthropic-version", "spoofed-version")

		b.prepareHeaders(req, "sk-ant-real-key")

		// Client-sent headers should be replaced with correct values
		assert.Equal(t, "sk-ant-real-key", req.Header.Get("x-api-key"))
		assert.Equal(t, anthropicAPIVersionHeader, req.Header.Get("anthropic-version"))
	})
}
