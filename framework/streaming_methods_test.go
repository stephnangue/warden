package framework

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testStreamingBackend() *StreamingBackend {
	sb := &StreamingBackend{
		StreamingPaths: []*StreamingPath{
			{
				Pattern:         "gateway",
				Handler:         func(_ context.Context, _ *logical.Request, _ *FieldData) error { return nil },
				HelpSynopsis:    "Gateway proxy",
				HelpDescription: "Proxies requests",
			},
			{
				Pattern:         "gateway/.*",
				Handler:         func(_ context.Context, _ *logical.Request, _ *FieldData) error { return nil },
				HelpSynopsis:    "Gateway proxy catch-all",
				HelpDescription: "Proxies requests with sub-paths",
			},
			{
				Pattern: "role/[^/]+/gateway",
				Handler: func(_ context.Context, _ *logical.Request, _ *FieldData) error { return nil },
			},
			{
				Pattern: "role/[^/]+/gateway/.*",
				Handler: func(_ context.Context, _ *logical.Request, _ *FieldData) error { return nil },
			},
		},
		TransparentConfig: &TransparentConfig{
			AutoAuthPath:    "auth/jwt/",
			DefaultAuthRole: "default",
		},
		Backend: &Backend{
			Help:         "test streaming backend",
			BackendType:  "test-stream",
			BackendClass: logical.ClassProvider,
			Paths: []*Path{
				{
					Pattern: "config",
					Operations: map[logical.Operation]OperationHandler{
						logical.ReadOperation: &PathOperation{
							Callback: func(_ context.Context, _ *logical.Request, _ *FieldData) (*logical.Response, error) {
								return &logical.Response{StatusCode: 200, Data: map[string]any{"ok": true}}, nil
							},
						},
					},
					HelpSynopsis: "Config",
				},
			},
		},
	}
	return sb
}

func TestStreamingBackend_TypeClassConfig(t *testing.T) {
	sb := testStreamingBackend()
	assert.Equal(t, "test-stream", sb.Type())
	assert.Equal(t, logical.ClassProvider, sb.Class())
	assert.Nil(t, sb.Config())
}

func TestStreamingBackend_TypeClassConfig_NilBackend(t *testing.T) {
	sb := &StreamingBackend{}
	assert.Equal(t, "", sb.Type())
	assert.Equal(t, logical.ClassUnknown, sb.Class())
	assert.Nil(t, sb.Config())
}

func TestStreamingBackend_Setup(t *testing.T) {
	sb := testStreamingBackend()
	err := sb.Setup(context.Background(), &logical.BackendConfig{
		Logger: newTestLogger(),
		Config: map[string]any{"k": "v"},
	})
	require.NoError(t, err)
	assert.Equal(t, "v", sb.Config()["k"])
}

func TestStreamingBackend_Setup_NilBackend(t *testing.T) {
	sb := &StreamingBackend{}
	err := sb.Setup(context.Background(), &logical.BackendConfig{Logger: newTestLogger()})
	assert.NoError(t, err)
}

func TestStreamingBackend_Initialize(t *testing.T) {
	sb := testStreamingBackend()
	assert.NoError(t, sb.Initialize(context.Background()))
}

func TestStreamingBackend_Initialize_NilBackend(t *testing.T) {
	sb := &StreamingBackend{}
	assert.NoError(t, sb.Initialize(context.Background()))
}

func TestStreamingBackend_Cleanup(t *testing.T) {
	called := false
	sb := testStreamingBackend()
	sb.Clean = func(_ context.Context) { called = true }
	sb.Cleanup(context.Background())
	assert.True(t, called)
}

func TestStreamingBackend_Cleanup_NilBackend(t *testing.T) {
	sb := &StreamingBackend{}
	sb.Cleanup(context.Background()) // should not panic
}

func TestStreamingBackend_ExtractToken(t *testing.T) {
	sb := testStreamingBackend()
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("X-Warden-Token", "test-token")
	assert.Equal(t, "test-token", sb.ExtractToken(req))
}

func TestStreamingBackend_ExtractToken_NilBackend(t *testing.T) {
	sb := &StreamingBackend{}
	req, _ := http.NewRequest("GET", "/", nil)
	assert.Equal(t, "", sb.ExtractToken(req))
}

func TestStreamingBackend_HandleExistenceCheck_NilBackend(t *testing.T) {
	sb := &StreamingBackend{}
	found, exists, err := sb.HandleExistenceCheck(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
	})
	assert.NoError(t, err)
	assert.False(t, found)
	assert.False(t, exists)
}

func TestStreamingBackend_HandleRequest_StandardPath(t *testing.T) {
	sb := testStreamingBackend()
	resp, err := sb.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
	})
	require.NoError(t, err)
	assert.Equal(t, true, resp.Data["ok"])
}

func TestStreamingBackend_HandleRequest_StreamingPath(t *testing.T) {
	sb := testStreamingBackend()
	rec := httptest.NewRecorder()
	httpReq := httptest.NewRequest("POST", "/gateway/v1/messages", nil)

	resp, err := sb.HandleRequest(context.Background(), &logical.Request{
		Operation:      logical.ReadOperation,
		Path:           "gateway/v1/messages",
		Streamed:       true,
		HTTPRequest:    httpReq,
		ResponseWriter: rec,
	})
	require.NoError(t, err)
	assert.True(t, resp.Streamed)
}

func TestStreamingBackend_HandleRequest_RootHelp(t *testing.T) {
	sb := testStreamingBackend()
	resp, err := sb.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.HelpOperation,
		Path:      "",
	})
	require.NoError(t, err)
	help := resp.Data["help"].(string)
	assert.Contains(t, help, "test streaming backend")
	assert.Contains(t, help, "Gateway proxy")
}

func TestStreamingBackend_HandleRequest_StreamingPathHelp(t *testing.T) {
	sb := testStreamingBackend()
	resp, err := sb.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.HelpOperation,
		Path:      "gateway",
	})
	require.NoError(t, err)
	assert.Contains(t, resp.Data["help"], "Gateway proxy")
}

func TestStreamingBackend_HandleRequest_UnsupportedPath(t *testing.T) {
	sb := &StreamingBackend{} // nil Backend
	_, err := sb.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "nonexistent",
	})
	assert.Error(t, err)
}

func TestStreamingBackend_SpecialPaths(t *testing.T) {
	sb := testStreamingBackend()
	sp := sb.SpecialPaths()
	require.NotNil(t, sp)
	assert.NotEmpty(t, sp.Stream)
}

func TestStreamingBackend_SpecialPaths_NilBackend(t *testing.T) {
	sb := &StreamingBackend{
		StreamingPaths: []*StreamingPath{
			{Pattern: "gateway/.*"},
		},
	}
	sp := sb.SpecialPaths()
	require.NotNil(t, sp)
	assert.NotEmpty(t, sp.Stream)
}

func TestStreamingBackend_TransparentMode(t *testing.T) {
	sb := testStreamingBackend()

	assert.True(t, sb.IsTransparentMode())
	assert.Equal(t, "auth/jwt/", sb.GetAutoAuthPath())
}

func TestStreamingBackend_TransparentMode_Nil(t *testing.T) {
	sb := &StreamingBackend{}
	assert.False(t, sb.IsTransparentMode())
	assert.Equal(t, "", sb.GetAutoAuthPath())
}

func TestStreamingBackend_GetAuthRole(t *testing.T) {
	sb := testStreamingBackend()

	t.Run("extracts from path", func(t *testing.T) {
		role := sb.GetAuthRole("role/admin/gateway/v1/messages", nil)
		assert.Equal(t, "admin", role)
	})

	t.Run("falls back to default", func(t *testing.T) {
		role := sb.GetAuthRole("gateway/v1/messages", nil)
		assert.Equal(t, "default", role)
	})

	t.Run("nil config", func(t *testing.T) {
		sb2 := &StreamingBackend{}
		assert.Equal(t, "", sb2.GetAuthRole("role/x/gateway", nil))
	})
}

func TestStreamingBackend_RewriteTransparentPath(t *testing.T) {
	sb := testStreamingBackend()

	t.Run("rewrites role path", func(t *testing.T) {
		result := sb.RewriteTransparentPath("role/admin/gateway/v1/messages")
		assert.Equal(t, "gateway/v1/messages", result)
	})

	t.Run("nil config", func(t *testing.T) {
		sb2 := &StreamingBackend{}
		assert.Equal(t, "some/path", sb2.RewriteTransparentPath("some/path"))
	})
}

func TestStreamingBackend_SetTransparentConfig(t *testing.T) {
	sb := testStreamingBackend()
	sb.SetTransparentConfig(&TransparentConfig{
		AutoAuthPath: "auth/cert/",
	})
	assert.Equal(t, "auth/cert/", sb.GetAutoAuthPath())
}

func TestStreamingBackend_IsTransparentPath(t *testing.T) {
	sb := testStreamingBackend()
	// Streaming paths with role/ prefix are transparent
	assert.True(t, sb.IsTransparentPath("role/admin/gateway/v1/messages"))
	assert.True(t, sb.IsTransparentPath("gateway/v1/messages"))
	assert.False(t, sb.IsTransparentPath("config"))
}

func TestDefaultPathRewriter(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"role/admin/gateway/v1/messages", "gateway/v1/messages"},
		{"role/reader/gateway", "gateway"},
		{"gateway/v1/messages", "gateway/v1/messages"}, // no role prefix, unchanged
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			assert.Equal(t, tc.expected, DefaultPathRewriter(tc.input))
		})
	}
}

func TestStreamingBackend_InitProxy(t *testing.T) {
	sb := &StreamingBackend{
		Backend: &Backend{},
	}
	sb.InitProxy(http.DefaultTransport)
	assert.NotNil(t, sb.Proxy)
}
