package framework

import (
	"context"
	"net/http"
	"testing"

	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestLogger() *logger.GatedLogger {
	config := &logger.Config{Level: logger.TraceLevel, Format: logger.DefaultFormat}
	gateConfig := logger.GatedWriterConfig{InitialState: logger.GateOpen}
	gl, _ := logger.NewGatedLogger(config, gateConfig)
	return gl
}

func testBackend() *Backend {
	return &Backend{
		Help:         "test backend help",
		BackendType:  "test",
		BackendClass: logical.ClassProvider,
		Paths: []*Path{
			{
				Pattern: "config",
				Fields: map[string]*FieldSchema{
					"name":  {Type: TypeString, Description: "The name"},
					"count": {Type: TypeInt, Default: 10, Description: "A count"},
				},
				Operations: map[logical.Operation]OperationHandler{
					logical.ReadOperation: &PathOperation{
						Callback: func(_ context.Context, _ *logical.Request, d *FieldData) (*logical.Response, error) {
							return &logical.Response{
								StatusCode: http.StatusOK,
								Data: map[string]any{
									"name":  d.Get("name"),
									"count": d.Get("count"),
								},
							}, nil
						},
						Summary: "Read config",
					},
					logical.UpdateOperation: &PathOperation{
						Callback: func(_ context.Context, _ *logical.Request, d *FieldData) (*logical.Response, error) {
							return &logical.Response{
								StatusCode: http.StatusOK,
								Data:       map[string]any{"message": "updated"},
							}, nil
						},
						Summary: "Update config",
					},
				},
				HelpSynopsis:    "Manage config",
				HelpDescription: "Full description of config management",
			},
			{
				Pattern: "items/" + GenericNameRegex("name"),
				Fields: map[string]*FieldSchema{
					"name": {Type: TypeString, Description: "Item name"},
				},
				Operations: map[logical.Operation]OperationHandler{
					logical.ReadOperation: &PathOperation{
						Callback: func(_ context.Context, _ *logical.Request, d *FieldData) (*logical.Response, error) {
							return &logical.Response{
								StatusCode: http.StatusOK,
								Data:       map[string]any{"name": d.Get("name")},
							}, nil
						},
					},
				},
				ExistenceCheck: func(_ context.Context, _ *logical.Request, d *FieldData) (bool, error) {
					name := d.Get("name").(string)
					return name == "exists", nil
				},
				HelpSynopsis: "Manage items",
			},
		},
	}
}

func TestBackend_TypeAndClass(t *testing.T) {
	b := testBackend()
	assert.Equal(t, "test", b.Type())
	assert.Equal(t, logical.ClassProvider, b.Class())
}

func TestBackend_Setup(t *testing.T) {
	b := testBackend()
	lg := newTestLogger()
	err := b.Setup(context.Background(), &logical.BackendConfig{
		Logger: lg,
		Config: map[string]any{"key": "value"},
	})
	require.NoError(t, err)
	assert.Equal(t, "value", b.Config()["key"])
}

func TestBackend_Initialize(t *testing.T) {
	t.Run("no InitializeFunc", func(t *testing.T) {
		b := testBackend()
		err := b.Initialize(context.Background())
		assert.NoError(t, err)
	})

	t.Run("with InitializeFunc", func(t *testing.T) {
		called := false
		b := &Backend{
			InitializeFunc: func(_ context.Context) error {
				called = true
				return nil
			},
		}
		err := b.Initialize(context.Background())
		assert.NoError(t, err)
		assert.True(t, called)
	})
}

func TestBackend_Cleanup(t *testing.T) {
	t.Run("no Clean func", func(t *testing.T) {
		b := testBackend()
		b.Cleanup(context.Background()) // should not panic
	})

	t.Run("with Clean func", func(t *testing.T) {
		called := false
		b := &Backend{
			Clean: func(_ context.Context) { called = true },
		}
		b.Cleanup(context.Background())
		assert.True(t, called)
	})
}

func TestBackend_SpecialPaths(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		b := testBackend()
		assert.Nil(t, b.SpecialPaths())
	})

	t.Run("set", func(t *testing.T) {
		b := &Backend{
			PathsSpecial: &logical.Paths{
				Unauthenticated: []string{"health"},
			},
		}
		sp := b.SpecialPaths()
		assert.Contains(t, sp.Unauthenticated, "health")
	})
}

func TestBackend_HandleRequest(t *testing.T) {
	b := testBackend()

	t.Run("read config", func(t *testing.T) {
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "config",
			Data:      map[string]any{"name": "test-name"},
		})
		require.NoError(t, err)
		assert.Equal(t, "test-name", resp.Data["name"])
		assert.Equal(t, 10, resp.Data["count"]) // default
	})

	t.Run("update config", func(t *testing.T) {
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config",
		})
		require.NoError(t, err)
		assert.Equal(t, "updated", resp.Data["message"])
	})

	t.Run("create falls back to update", func(t *testing.T) {
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "config",
		})
		require.NoError(t, err)
		assert.Equal(t, "updated", resp.Data["message"])
	})

	t.Run("path with captures", func(t *testing.T) {
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "items/my-item",
		})
		require.NoError(t, err)
		assert.Equal(t, "my-item", resp.Data["name"])
	})

	t.Run("unsupported path", func(t *testing.T) {
		_, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "nonexistent",
		})
		assert.Error(t, err)
	})

	t.Run("unsupported operation", func(t *testing.T) {
		_, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      "config",
		})
		assert.Error(t, err)
	})

	t.Run("root help", func(t *testing.T) {
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.HelpOperation,
			Path:      "",
		})
		require.NoError(t, err)
		assert.Contains(t, resp.Data["help"], "test backend help")
	})

	t.Run("path help", func(t *testing.T) {
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.HelpOperation,
			Path:      "config",
		})
		require.NoError(t, err)
		assert.Contains(t, resp.Data["help"], "Manage config")
	})

	t.Run("unrecognized params warned", func(t *testing.T) {
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "config",
			Data:      map[string]any{"unknown_field": "val"},
		})
		require.NoError(t, err)
		require.True(t, len(resp.Warnings) > 0)
		assert.Contains(t, resp.Warnings[0], "unknown_field")
	})
}

func TestBackend_HandleExistenceCheck(t *testing.T) {
	b := testBackend()

	t.Run("existing item", func(t *testing.T) {
		found, exists, err := b.HandleExistenceCheck(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "items/exists",
		})
		require.NoError(t, err)
		assert.True(t, found)
		assert.True(t, exists)
	})

	t.Run("non-existing item", func(t *testing.T) {
		found, exists, err := b.HandleExistenceCheck(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "items/nope",
		})
		require.NoError(t, err)
		assert.True(t, found)
		assert.False(t, exists)
	})

	t.Run("path without existence check", func(t *testing.T) {
		found, _, err := b.HandleExistenceCheck(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config",
		})
		require.NoError(t, err)
		assert.False(t, found)
	})

	t.Run("wrong operation type", func(t *testing.T) {
		_, _, err := b.HandleExistenceCheck(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "items/test",
		})
		assert.Error(t, err)
	})

	t.Run("unsupported path", func(t *testing.T) {
		_, _, err := b.HandleExistenceCheck(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "nonexistent",
		})
		assert.Error(t, err)
	})
}

func TestBackend_Route(t *testing.T) {
	b := testBackend()

	t.Run("matches config", func(t *testing.T) {
		p := b.Route("config")
		require.NotNil(t, p)
		assert.Equal(t, "^config$", p.Pattern)
	})

	t.Run("matches items", func(t *testing.T) {
		p := b.Route("items/my-item")
		require.NotNil(t, p)
	})

	t.Run("no match", func(t *testing.T) {
		p := b.Route("nonexistent")
		assert.Nil(t, p)
	})
}

func TestBackend_ExtractToken(t *testing.T) {
	t.Run("default extractor", func(t *testing.T) {
		b := &Backend{}
		req, _ := http.NewRequest("GET", "/", nil)
		req.Header.Set("X-Warden-Token", "my-token")
		assert.Equal(t, "my-token", b.ExtractToken(req))
	})

	t.Run("custom extractor", func(t *testing.T) {
		b := &Backend{
			TokenExtractor: func(r *http.Request) string {
				return r.Header.Get("X-Custom")
			},
		}
		req, _ := http.NewRequest("GET", "/", nil)
		req.Header.Set("X-Custom", "custom-token")
		assert.Equal(t, "custom-token", b.ExtractToken(req))
	})
}

func TestDefaultTokenExtractor(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		expected string
	}{
		{"X-Warden-Token", map[string]string{"X-Warden-Token": "wt"}, "wt"},
		{"Bearer token", map[string]string{"Authorization": "Bearer bt"}, "bt"},
		{"case insensitive Bearer", map[string]string{"Authorization": "bearer bt"}, "bt"},
		{"X-Warden-Token priority", map[string]string{"X-Warden-Token": "wt", "Authorization": "Bearer bt"}, "wt"},
		{"no token", map[string]string{}, ""},
		{"non-Bearer auth ignored", map[string]string{"Authorization": "Basic abc"}, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "/", nil)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			assert.Equal(t, tc.expected, DefaultTokenExtractor(req))
		})
	}
}
