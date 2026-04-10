package scaleway

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/sigv4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- test helpers ---

type inmemStorage struct {
	mu   sync.RWMutex
	data map[string]*sdklogical.StorageEntry
}

func newInmemStorage() *inmemStorage {
	return &inmemStorage{data: make(map[string]*sdklogical.StorageEntry)}
}

func (s *inmemStorage) List(ctx context.Context, prefix string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var keys []string
	for k := range s.data {
		keys = append(keys, k)
	}
	return keys, nil
}

func (s *inmemStorage) ListPage(ctx context.Context, prefix string, after string, limit int) ([]string, error) {
	return s.List(ctx, prefix)
}

func (s *inmemStorage) Get(ctx context.Context, key string) (*sdklogical.StorageEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data[key], nil
}

func (s *inmemStorage) Put(ctx context.Context, entry *sdklogical.StorageEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[entry.Key] = entry
	return nil
}

func (s *inmemStorage) Delete(ctx context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, key)
	return nil
}

func createTestLogger() *logger.GatedLogger {
	config := &logger.Config{
		Level:   logger.TraceLevel,
		Format:  logger.DefaultFormat,
		Outputs: []io.Writer{io.Discard},
	}
	gl, _ := logger.NewGatedLogger(config, logger.GatedWriterConfig{
		Underlying:   io.Discard,
		InitialState: logger.GateOpen,
	})
	return gl
}

func makeFieldData(path *framework.Path, raw map[string]interface{}) *framework.FieldData {
	return &framework.FieldData{
		Raw:    raw,
		Schema: path.Fields,
	}
}

// --- Factory tests ---

func TestFactory(t *testing.T) {
	storage := newInmemStorage()
	ctx := context.Background()
	conf := &logical.BackendConfig{
		StorageView: storage,
		Logger:      createTestLogger(),
	}

	b, err := Factory(ctx, conf)
	require.NoError(t, err)
	require.NotNil(t, b)

	sb := b.(*scalewayBackend)
	assert.Equal(t, DefaultScalewayURL, sb.scalewayURL)
	assert.Equal(t, framework.DefaultMaxBodySize, sb.MaxBodySize)
	assert.Equal(t, DefaultScalewayTimeout, sb.Timeout)
	assert.NotNil(t, sb.s3Signer)
}

func TestFactory_WithConfig(t *testing.T) {
	storage := newInmemStorage()
	ctx := context.Background()
	conf := &logical.BackendConfig{
		StorageView: storage,
		Logger:      createTestLogger(),
		Config: map[string]any{
			"scaleway_url":  "https://api.fr-par.scaleway.com",
			"max_body_size": int64(5242880),
			"timeout":       "60s",
		},
	}

	b, err := Factory(ctx, conf)
	require.NoError(t, err)

	sb := b.(*scalewayBackend)
	assert.Equal(t, "https://api.fr-par.scaleway.com", sb.scalewayURL)
	assert.Equal(t, int64(5242880), sb.MaxBodySize)
}

func TestFactory_InvalidConfig(t *testing.T) {
	storage := newInmemStorage()
	ctx := context.Background()
	conf := &logical.BackendConfig{
		StorageView: storage,
		Logger:      createTestLogger(),
		Config: map[string]any{
			"unknown_key": "value",
		},
	}

	_, err := Factory(ctx, conf)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown configuration key")
}

// --- Config path tests ---

func TestPathConfig_ReadDefaults(t *testing.T) {
	storage := newInmemStorage()
	ctx := context.Background()
	conf := &logical.BackendConfig{
		StorageView: storage,
		Logger:      createTestLogger(),
	}

	b, err := Factory(ctx, conf)
	require.NoError(t, err)

	sb := b.(*scalewayBackend)
	path := sb.pathConfig()

	resp, err := sb.handleConfigRead(ctx, &logical.Request{}, makeFieldData(path, nil))
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, DefaultScalewayURL, resp.Data["scaleway_url"])
}

func TestPathConfig_Write(t *testing.T) {
	storage := newInmemStorage()
	ctx := context.Background()
	conf := &logical.BackendConfig{
		StorageView: storage,
		Logger:      createTestLogger(),
	}

	b, err := Factory(ctx, conf)
	require.NoError(t, err)

	sb := b.(*scalewayBackend)
	path := sb.pathConfig()

	raw := map[string]interface{}{
		"scaleway_url":   "https://api.nl-ams.scaleway.com",
		"timeout":        30,
		"auto_auth_path": "auth/jwt/",
		"default_role":   "reader",
	}

	resp, err := sb.handleConfigWrite(ctx, &logical.Request{}, makeFieldData(path, raw))
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	assert.Equal(t, "https://api.nl-ams.scaleway.com", sb.scalewayURL)
}

func TestPathConfig_Write_MissingAutoAuthPath(t *testing.T) {
	storage := newInmemStorage()
	ctx := context.Background()
	conf := &logical.BackendConfig{
		StorageView: storage,
		Logger:      createTestLogger(),
	}

	b, err := Factory(ctx, conf)
	require.NoError(t, err)

	sb := b.(*scalewayBackend)
	path := sb.pathConfig()

	raw := map[string]interface{}{
		"scaleway_url": "https://api.scaleway.com",
	}

	resp, err := sb.handleConfigWrite(ctx, &logical.Request{}, makeFieldData(path, raw))
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// --- Token extraction tests ---

func TestExtractToken(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		expected string
	}{
		{
			name:     "X-Warden-Token",
			headers:  map[string]string{"X-Warden-Token": "my-token"},
			expected: "my-token",
		},
		{
			name:     "Bearer token",
			headers:  map[string]string{"Authorization": "Bearer my-jwt"},
			expected: "my-jwt",
		},
		{
			name:     "SigV4 with JWT access key",
			headers:  map[string]string{"Authorization": "AWS4-HMAC-SHA256 Credential=eyJhbGciOiJSUzI1NiJ9/20260410/fr-par/s3/aws4_request, SignedHeaders=host, Signature=abc123"},
			expected: "eyJhbGciOiJSUzI1NiJ9",
		},
		{
			name:     "SigV4 with role name access key",
			headers:  map[string]string{"Authorization": "AWS4-HMAC-SHA256 Credential=my-role/20260410/fr-par/s3/aws4_request, SignedHeaders=host, Signature=abc123"},
			expected: "my-role",
		},
		{
			name:     "no auth headers",
			headers:  map[string]string{},
			expected: "",
		},
		{
			name:     "X-Warden-Token takes precedence",
			headers:  map[string]string{"X-Warden-Token": "warden-token", "Authorization": "Bearer other"},
			expected: "warden-token",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := http.NewRequest("GET", "/", nil)
			for k, v := range tt.headers {
				r.Header.Set(k, v)
			}
			assert.Equal(t, tt.expected, extractToken(r))
		})
	}
}

// --- TransparentAuthRoleExtractor tests ---

func TestGetAuthRoleFromRequest(t *testing.T) {
	b := &scalewayBackend{}

	tests := []struct {
		name       string
		authHeader string
		wantRole   string
		wantOK     bool
	}{
		{
			name:       "cert transparent - role name as access_key_id",
			authHeader: "AWS4-HMAC-SHA256 Credential=scaleway-admin/20260410/fr-par/s3/aws4_request, SignedHeaders=host, Signature=abc",
			wantRole:   "scaleway-admin",
			wantOK:     true,
		},
		{
			name:       "JWT transparent - JWT as access_key_id - no role",
			authHeader: "AWS4-HMAC-SHA256 Credential=eyJhbGciOiJSUzI1NiJ9/20260410/fr-par/s3/aws4_request, SignedHeaders=host, Signature=abc",
			wantRole:   "",
			wantOK:     false,
		},
		{
			name:       "non-SigV4 request",
			authHeader: "Bearer some-token",
			wantRole:   "",
			wantOK:     false,
		},
		{
			name:       "empty authorization header",
			authHeader: "",
			wantRole:   "",
			wantOK:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := http.NewRequest("GET", "/", nil)
			if tt.authHeader != "" {
				r.Header.Set("Authorization", tt.authHeader)
			}
			role, ok := b.GetAuthRoleFromRequest(r)
			assert.Equal(t, tt.wantRole, role)
			assert.Equal(t, tt.wantOK, ok)
		})
	}
}

// --- IsSigV4Request detection tests ---

func TestIsSigV4RequestDetection(t *testing.T) {
	t.Run("SigV4 request", func(t *testing.T) {
		r, _ := http.NewRequest("GET", "/", nil)
		r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=test/20260410/fr-par/s3/aws4_request")
		assert.True(t, sigv4.IsSigV4Request(r))
	})

	t.Run("Bearer request", func(t *testing.T) {
		r, _ := http.NewRequest("GET", "/", nil)
		r.Header.Set("Authorization", "Bearer some-token")
		assert.False(t, sigv4.IsSigV4Request(r))
	})

	t.Run("no auth header", func(t *testing.T) {
		r, _ := http.NewRequest("GET", "/", nil)
		assert.False(t, sigv4.IsSigV4Request(r))
	})
}

// --- Credential extraction tests ---

func TestGetSecretKey(t *testing.T) {
	b := &scalewayBackend{}

	t.Run("valid scaleway_keys credential", func(t *testing.T) {
		req := &logical.Request{
			Credential: &credential.Credential{
				Type: credential.TypeScalewayKeys,
				Data: map[string]string{
					"access_key": "SCWXXXXXXXXXXXXXXXXX",
					"secret_key": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
				},
			},
		}
		key, err := b.getSecretKey(req)
		require.NoError(t, err)
		assert.Equal(t, "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", key)
	})

	t.Run("missing secret_key field", func(t *testing.T) {
		req := &logical.Request{
			Credential: &credential.Credential{
				Type: credential.TypeScalewayKeys,
				Data: map[string]string{
					"access_key": "SCWXXXXXXXXXXXXXXXXX",
				},
			},
		}
		_, err := b.getSecretKey(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "secret_key")
	})

	t.Run("nil credential", func(t *testing.T) {
		req := &logical.Request{}
		_, err := b.getSecretKey(req)
		require.Error(t, err)
	})

	t.Run("unsupported credential type", func(t *testing.T) {
		req := &logical.Request{
			Credential: &credential.Credential{
				Type: credential.TypeAPIKey,
				Data: map[string]string{"api_key": "test"},
			},
		}
		_, err := b.getSecretKey(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported")
	})
}

func TestGetS3Credentials(t *testing.T) {
	b := &scalewayBackend{}

	t.Run("valid credentials", func(t *testing.T) {
		req := &logical.Request{
			Credential: &credential.Credential{
				Type: credential.TypeScalewayKeys,
				Data: map[string]string{
					"access_key": "SCWXXXXXXXXXXXXXXXXX",
					"secret_key": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
				},
			},
		}
		creds, err := b.getS3Credentials(req)
		require.NoError(t, err)
		assert.Equal(t, "SCWXXXXXXXXXXXXXXXXX", creds.AccessKeyID)
		assert.Equal(t, "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", creds.SecretAccessKey)
	})

	t.Run("missing access_key", func(t *testing.T) {
		req := &logical.Request{
			Credential: &credential.Credential{
				Type: credential.TypeScalewayKeys,
				Data: map[string]string{
					"secret_key": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
				},
			},
		}
		_, err := b.getS3Credentials(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "access_key or secret_key")
	})

	t.Run("nil credential", func(t *testing.T) {
		req := &logical.Request{}
		_, err := b.getS3Credentials(req)
		require.Error(t, err)
	})
}

// --- API gateway tests ---

func TestHandleAPIRequest(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "warden-scaleway-proxy", r.Header.Get("User-Agent"))
		assert.NotEmpty(t, r.Header.Get("X-Auth-Token"))
		assert.Empty(t, r.Header.Get("X-Warden-Token"))
		assert.Equal(t, "/instance/v1/zones/fr-par-1/servers", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"servers":[]}`))
	}))
	defer upstream.Close()

	storage := newInmemStorage()
	ctx := context.Background()
	conf := &logical.BackendConfig{
		StorageView: storage,
		Logger:      createTestLogger(),
	}

	b, err := Factory(ctx, conf)
	require.NoError(t, err)
	sb := b.(*scalewayBackend)
	sb.scalewayURL = upstream.URL // set after factory to bypass HTTPS validation

	rec := httptest.NewRecorder()
	httpReq := httptest.NewRequest("GET", "/instance/v1/zones/fr-par-1/servers", nil)
	httpReq.Header.Set("X-Warden-Token", "should-be-stripped")

	req := &logical.Request{
		HTTPRequest:    httpReq,
		ResponseWriter: rec,
		Credential: &credential.Credential{
			Type: credential.TypeScalewayKeys,
			Data: map[string]string{
				"access_key": "SCWXXXXXXXXXXXXXXXXX",
				"secret_key": "test-secret-key",
			},
		},
	}

	sb.handleAPIRequest(ctx, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "servers")
}

// --- Config validation tests ---

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  map[string]any
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid config",
			config:  map[string]any{"scaleway_url": "https://api.scaleway.com", "timeout": "30s"},
			wantErr: false,
		},
		{
			name:    "unknown key",
			config:  map[string]any{"unknown": "value"},
			wantErr: true,
			errMsg:  "unknown configuration key",
		},
		{
			name:    "max_body_size too large",
			config:  map[string]any{"max_body_size": int64(200000000)},
			wantErr: true,
			errMsg:  "must not exceed",
		},
		{
			name:    "invalid timeout format",
			config:  map[string]any{"timeout": "invalid"},
			wantErr: true,
			errMsg:  "invalid timeout format",
		},
		{
			name:    "empty config",
			config:  map[string]any{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateConfig(tt.config)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// --- SensitiveConfigFields test ---

func TestSensitiveConfigFields(t *testing.T) {
	storage := newInmemStorage()
	ctx := context.Background()
	conf := &logical.BackendConfig{
		StorageView: storage,
		Logger:      createTestLogger(),
	}

	b, err := Factory(ctx, conf)
	require.NoError(t, err)

	sb := b.(*scalewayBackend)
	assert.Empty(t, sb.SensitiveConfigFields())
}

// --- Paths test ---

func TestPaths(t *testing.T) {
	b := &scalewayBackend{}
	paths := b.paths()
	require.Len(t, paths, 1)
	assert.Equal(t, "config", paths[0].Pattern)
}

// --- Transport tests ---

func TestShutdownHTTPTransport(t *testing.T) {
	// Should not panic
	ShutdownHTTPTransport()
}
