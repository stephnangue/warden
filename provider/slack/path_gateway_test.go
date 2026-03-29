package slack

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildTargetURL(t *testing.T) {
	b := &slackBackend{
		slackURL: "https://slack.com/api",
	}

	tests := []struct {
		name     string
		path     string
		query    string
		expected string
		wantErr  bool
	}{
		{
			name:     "chat.postMessage",
			path:     "/slack/gateway/chat.postMessage",
			expected: "https://slack.com/api/chat.postMessage",
		},
		{
			name:     "conversations.list",
			path:     "/slack/gateway/conversations.list",
			expected: "https://slack.com/api/conversations.list",
		},
		{
			name:     "conversations.history",
			path:     "/slack/gateway/conversations.history",
			expected: "https://slack.com/api/conversations.history",
		},
		{
			name:     "auth.test",
			path:     "/slack/gateway/auth.test",
			expected: "https://slack.com/api/auth.test",
		},
		{
			name:     "path with query",
			path:     "/slack/gateway/conversations.list",
			query:    "limit=100&cursor=abc",
			expected: "https://slack.com/api/conversations.list?limit=100&cursor=abc",
		},
		{
			name:     "bare gateway",
			path:     "/slack/gateway",
			expected: "https://slack.com/api/",
		},
		{
			name:     "gateway with trailing slash",
			path:     "/slack/gateway/",
			expected: "https://slack.com/api/",
		},
		{
			name:    "no gateway marker",
			path:    "/slack/chat.postMessage",
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
	b := &slackBackend{
		slackURL: "https://slack.example.com/api",
	}

	result, err := b.buildTargetURL("/custom/gateway/chat.postMessage", "")
	assert.NoError(t, err)
	assert.Equal(t, "https://slack.example.com/api/chat.postMessage", result)
}

func TestPrepareHeaders(t *testing.T) {
	b := &slackBackend{}

	t.Run("removes security headers and injects bot token", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "https://slack.com/api/chat.postMessage", nil)
		req.Header.Set("Authorization", "Bearer warden-token")
		req.Header.Set("X-Warden-Token", "warden-token")
		req.Header.Set("X-Custom", "keep-me")

		b.prepareHeaders(req, "xoxb-test-token")

		assert.Equal(t, "Bearer xoxb-test-token", req.Header.Get("Authorization"))
		assert.Equal(t, "", req.Header.Get("X-Warden-Token"))
		assert.Equal(t, "keep-me", req.Header.Get("X-Custom"))
	})

	t.Run("injects default headers", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "https://slack.com/api/chat.postMessage", nil)

		b.prepareHeaders(req, "xoxb-test-token")

		assert.Equal(t, "application/json", req.Header.Get("Accept"))
		assert.Equal(t, "warden-slack-proxy", req.Header.Get("User-Agent"))
	})

	t.Run("preserves client-set Accept header", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "https://slack.com/api/chat.postMessage", nil)
		req.Header.Set("Accept", "text/plain")

		b.prepareHeaders(req, "xoxb-test-token")

		assert.Equal(t, "text/plain", req.Header.Get("Accept"))
	})

	t.Run("removes hop-by-hop headers", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "https://slack.com/api/chat.postMessage", nil)
		req.Header.Set("Connection", "keep-alive")
		req.Header.Set("Transfer-Encoding", "chunked")
		req.Header.Set("Proxy-Authorization", "Basic abc")

		b.prepareHeaders(req, "xoxb-test-token")

		assert.Equal(t, "", req.Header.Get("Connection"))
		assert.Equal(t, "", req.Header.Get("Transfer-Encoding"))
		assert.Equal(t, "", req.Header.Get("Proxy-Authorization"))
	})

	t.Run("removes Connection-listed headers", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "https://slack.com/api/chat.postMessage", nil)
		req.Header.Set("Connection", "X-Custom-Hop")
		req.Header.Set("X-Custom-Hop", "should-be-removed")

		b.prepareHeaders(req, "xoxb-test-token")

		assert.Equal(t, "", req.Header.Get("X-Custom-Hop"))
	})

	t.Run("removes proxy headers", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "https://slack.com/api/chat.postMessage", nil)
		req.Header.Set("X-Forwarded-For", "10.0.0.1")
		req.Header.Set("X-Real-Ip", "10.0.0.1")
		req.Header.Set("Forwarded", "for=10.0.0.1")

		b.prepareHeaders(req, "xoxb-test-token")

		assert.Equal(t, "", req.Header.Get("X-Forwarded-For"))
		assert.Equal(t, "", req.Header.Get("X-Real-Ip"))
		assert.Equal(t, "", req.Header.Get("Forwarded"))
	})

	t.Run("empty token does not set Authorization", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "https://slack.com/api/chat.postMessage", nil)

		b.prepareHeaders(req, "")

		assert.Equal(t, "", req.Header.Get("Authorization"))
	})
}
