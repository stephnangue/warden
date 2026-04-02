package gitlab

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"sync"
	"testing"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
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

func (s *inmemStorage) List(_ context.Context, prefix string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var keys []string
	for k := range s.data {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			keys = append(keys, k[len(prefix):])
		}
	}
	return keys, nil
}

func (s *inmemStorage) Get(_ context.Context, key string) (*sdklogical.StorageEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data[key], nil
}

func (s *inmemStorage) Put(_ context.Context, entry *sdklogical.StorageEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[entry.Key] = entry
	return nil
}

func (s *inmemStorage) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, key)
	return nil
}

func (s *inmemStorage) ListPage(_ context.Context, prefix string, _ string, _ int) ([]string, error) {
	return s.List(context.Background(), prefix)
}

func testLogger() *logger.GatedLogger {
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

// --- Factory tests ---

func TestFactory(t *testing.T) {
	storage := newInmemStorage()
	ctx := context.Background()
	conf := &logical.BackendConfig{
		StorageView: storage,
		Logger:      testLogger(),
	}
	b, err := Factory(ctx, conf)
	require.NoError(t, err)
	gb := b.(*gitlabBackend)
	assert.Equal(t, "gitlab", gb.Type())
	assert.Equal(t, logical.ClassProvider, gb.Class())
	assert.Equal(t, framework.DefaultMaxBodySize, gb.MaxBodySize)
	assert.Equal(t, framework.DefaultTimeout, gb.Timeout)
}

func TestFactory_WithConfig(t *testing.T) {
	storage := newInmemStorage()
	ctx := context.Background()
	conf := &logical.BackendConfig{
		StorageView: storage,
		Logger:      testLogger(),
		Config: map[string]any{
			"gitlab_address": "https://gitlab.example.com",
			"max_body_size":  int64(5242880),
			"timeout":        "60s",
		},
	}
	b, err := Factory(ctx, conf)
	require.NoError(t, err)
	gb := b.(*gitlabBackend)
	assert.Equal(t, "https://gitlab.example.com", gb.gitlabAddress)
	assert.Equal(t, int64(5242880), gb.MaxBodySize)
	assert.Equal(t, 60*time.Second, gb.Timeout)
}

func TestFactory_InvalidConfig(t *testing.T) {
	storage := newInmemStorage()
	ctx := context.Background()
	conf := &logical.BackendConfig{
		StorageView: storage,
		Logger:      testLogger(),
		Config: map[string]any{
			"gitlab_address": "ftp://bad-scheme",
		},
	}
	_, err := Factory(ctx, conf)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid configuration")
}

func TestFactory_MissingAddress(t *testing.T) {
	storage := newInmemStorage()
	ctx := context.Background()
	conf := &logical.BackendConfig{
		StorageView: storage,
		Logger:      testLogger(),
		Config: map[string]any{
			"timeout": "30s",
		},
	}
	_, err := Factory(ctx, conf)
	assert.Error(t, err)
}

func TestFactory_ShutdownHook(t *testing.T) {
	storage := newInmemStorage()
	ctx := context.Background()
	hookCalled := false
	conf := &logical.BackendConfig{
		StorageView: storage,
		Logger:      testLogger(),
		RegisterShutdownHook: func(name string, fn func()) {
			hookCalled = true
			assert.Equal(t, "gitlab-transport", name)
		},
	}
	_, err := Factory(ctx, conf)
	require.NoError(t, err)
	assert.True(t, hookCalled)
}

// --- Initialize tests ---

func TestInitialize_NoStorage(t *testing.T) {
	b := &gitlabBackend{
		StreamingBackend: &framework.StreamingBackend{},
	}
	err := b.Initialize(context.Background())
	assert.NoError(t, err)
}

func TestInitialize_EmptyStorage(t *testing.T) {
	storage := newInmemStorage()
	b := &gitlabBackend{
		StreamingBackend: &framework.StreamingBackend{
			StorageView:       storage,
			TransparentConfig: &framework.TransparentConfig{},
		},
	}
	err := b.Initialize(context.Background())
	assert.NoError(t, err)
}

func TestInitialize_ExistingConfig(t *testing.T) {
	storage := newInmemStorage()
	entry, _ := sdklogical.StorageEntryJSON("config", map[string]any{
		"gitlab_address": "https://gitlab.example.com",
		"max_body_size":  int64(5242880),
		"timeout":        "60s",
		"auto_auth_path": "auth/jwt/",
		"default_role":   "reader",
	})
	_ = storage.Put(context.Background(), entry)

	b := &gitlabBackend{
		StreamingBackend: &framework.StreamingBackend{
			StorageView:       storage,
			TransparentConfig: &framework.TransparentConfig{},
		},
	}

	err := b.Initialize(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "https://gitlab.example.com", b.gitlabAddress)
	assert.Equal(t, int64(5242880), b.MaxBodySize)
	assert.Equal(t, 60*time.Second, b.Timeout)
}

// --- SensitiveConfigFields ---

func TestSensitiveConfigFields(t *testing.T) {
	b := &gitlabBackend{}
	assert.Empty(t, b.SensitiveConfigFields())
}

// --- paths ---

func TestPaths(t *testing.T) {
	b := &gitlabBackend{}
	paths := b.paths()
	require.Len(t, paths, 1)
	assert.Equal(t, "config", paths[0].Pattern)
}

// --- ShutdownHTTPTransport ---

func TestShutdownHTTPTransport(t *testing.T) {
	ShutdownHTTPTransport()
}

// --- pathConfig ---

func TestPathConfig_Schema(t *testing.T) {
	b := &gitlabBackend{}
	path := b.pathConfig()

	assert.Equal(t, "config", path.Pattern)
	assert.NotNil(t, path.Fields["gitlab_address"])
	assert.NotNil(t, path.Fields["max_body_size"])
	assert.NotNil(t, path.Fields["timeout"])
	assert.NotNil(t, path.Fields["auto_auth_path"])
	assert.NotNil(t, path.Fields["default_role"])

	assert.True(t, path.Fields["gitlab_address"].Required)
	assert.Equal(t, framework.TypeString, path.Fields["gitlab_address"].Type)
	assert.Equal(t, framework.TypeInt64, path.Fields["max_body_size"].Type)

	assert.NotNil(t, path.Operations[logical.ReadOperation])
	assert.NotNil(t, path.Operations[logical.UpdateOperation])
}

// --- handleConfigRead ---

func TestHandleConfigRead(t *testing.T) {
	b := &gitlabBackend{
		gitlabAddress: "https://gitlab.com",
		StreamingBackend: &framework.StreamingBackend{
			MaxBodySize:       framework.DefaultMaxBodySize,
			Timeout:           30 * time.Second,
			TransparentConfig: &framework.TransparentConfig{AutoAuthPath: "auth/jwt/", DefaultAuthRole: "reader"},
		},
	}

	resp, err := b.handleConfigRead(context.Background(), nil, nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "https://gitlab.com", resp.Data["gitlab_address"])
	assert.Equal(t, framework.DefaultMaxBodySize, resp.Data["max_body_size"])
	assert.Equal(t, (30 * time.Second).String(), resp.Data["timeout"])
	assert.Equal(t, "auth/jwt/", resp.Data["auto_auth_path"])
	assert.Equal(t, "reader", resp.Data["default_role"])
}

// --- handleConfigWrite ---

func TestHandleConfigWrite(t *testing.T) {
	b := &gitlabBackend{
		StreamingBackend: &framework.StreamingBackend{
			TransparentConfig: &framework.TransparentConfig{},
		},
	}
	path := b.pathConfig()

	t.Run("successful update", func(t *testing.T) {
		fd := &framework.FieldData{
			Raw: map[string]interface{}{
				"gitlab_address": "https://gitlab.example.com",
				"timeout":        60,
				"auto_auth_path": "auth/jwt/",
				"default_role":   "admin",
			},
			Schema: path.Fields,
		}
		resp, err := b.handleConfigWrite(context.Background(), nil, fd)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "https://gitlab.example.com", b.gitlabAddress)
	})

	t.Run("invalid address", func(t *testing.T) {
		fd := &framework.FieldData{
			Raw: map[string]interface{}{
				"gitlab_address": "ftp://bad",
				"auto_auth_path": "auth/jwt/",
			},
			Schema: path.Fields,
		}
		resp, err := b.handleConfigWrite(context.Background(), nil, fd)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("missing auto_auth_path", func(t *testing.T) {
		b.StreamingBackend.SetTransparentConfig(&framework.TransparentConfig{})
		fd := &framework.FieldData{
			Raw: map[string]interface{}{
				"gitlab_address": "https://gitlab.com",
			},
			Schema: path.Fields,
		}
		resp, err := b.handleConfigWrite(context.Background(), nil, fd)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("persists to storage", func(t *testing.T) {
		storage := newInmemStorage()
		b.StorageView = storage
		b.StreamingBackend.SetTransparentConfig(&framework.TransparentConfig{})
		fd := &framework.FieldData{
			Raw: map[string]interface{}{
				"gitlab_address": "https://gitlab.com",
				"auto_auth_path": "auth/cert/",
			},
			Schema: path.Fields,
		}
		resp, err := b.handleConfigWrite(context.Background(), nil, fd)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		entry, err := storage.Get(context.Background(), "config")
		require.NoError(t, err)
		require.NotNil(t, entry)
	})
}

// --- ValidateConfig ---

func TestValidateConfig(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		err := ValidateConfig(map[string]any{
			"gitlab_address": "https://gitlab.com",
		})
		assert.NoError(t, err)
	})

	t.Run("missing address", func(t *testing.T) {
		err := ValidateConfig(map[string]any{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "required")
	})

	t.Run("bad scheme", func(t *testing.T) {
		err := ValidateConfig(map[string]any{
			"gitlab_address": "ftp://gitlab.com",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "scheme")
	})
}

// --- validateGitLabAddress ---

func TestValidateGitLabAddress(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		wantErr bool
	}{
		{"valid https", "https://gitlab.com", false},
		{"valid http", "http://localhost:8080", false},
		{"empty", "", true},
		{"no scheme", "gitlab.com", true},
		{"ftp", "ftp://gitlab.com", true},
		{"no host", "https://", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateGitLabAddress(tt.addr)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// --- parseConfig ---

func TestParseConfig(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		config := parseConfig(map[string]any{})
		assert.Equal(t, framework.DefaultMaxBodySize, config.MaxBodySize)
		assert.Equal(t, framework.DefaultTimeout, config.Timeout)
		assert.Empty(t, config.GitLabAddress)
	})

	t.Run("all fields", func(t *testing.T) {
		config := parseConfig(map[string]any{
			"gitlab_address": "https://gitlab.com",
			"max_body_size":  int64(5242880),
			"timeout":        "60s",
		})
		assert.Equal(t, "https://gitlab.com", config.GitLabAddress)
		assert.Equal(t, int64(5242880), config.MaxBodySize)
		assert.Equal(t, 60*time.Second, config.Timeout)
	})

	t.Run("max_body_size types", func(t *testing.T) {
		for _, v := range []any{int(1024), int64(1024), float64(1024), "1024"} {
			config := parseConfig(map[string]any{"max_body_size": v})
			assert.Equal(t, int64(1024), config.MaxBodySize)
		}
	})

	t.Run("timeout types", func(t *testing.T) {
		config := parseConfig(map[string]any{"timeout": 45})
		assert.Equal(t, 45*time.Second, config.Timeout)

		config = parseConfig(map[string]any{"timeout": float64(30)})
		assert.Equal(t, 30*time.Second, config.Timeout)

		config = parseConfig(map[string]any{"timeout": "2m"})
		assert.Equal(t, 2*time.Minute, config.Timeout)
	})

	t.Run("negative values use defaults", func(t *testing.T) {
		config := parseConfig(map[string]any{"max_body_size": -1, "timeout": -5})
		assert.Equal(t, framework.DefaultMaxBodySize, config.MaxBodySize)
		assert.Equal(t, framework.DefaultTimeout, config.Timeout)
	})
}

// --- extractToken ---

func TestExtractToken(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		expected string
	}{
		{
			name:     "PRIVATE-TOKEN header",
			headers:  map[string]string{"PRIVATE-TOKEN": "glpat-test-123"},
			expected: "glpat-test-123",
		},
		{
			name:     "Authorization Bearer",
			headers:  map[string]string{"Authorization": "Bearer my-token"},
			expected: "my-token",
		},
		{
			name:     "X-Warden-Token",
			headers:  map[string]string{"X-Warden-Token": "warden-tok"},
			expected: "warden-tok",
		},
		{
			name:     "PRIVATE-TOKEN takes precedence",
			headers:  map[string]string{"PRIVATE-TOKEN": "pat", "Authorization": "Bearer bearer-tok"},
			expected: "pat",
		},
		{
			name:     "no token",
			headers:  map[string]string{},
			expected: "",
		},
		{
			name:     "Authorization without Bearer",
			headers:  map[string]string{"Authorization": "Basic abc"},
			expected: "",
		},
		{
			name:     "Authorization too short",
			headers:  map[string]string{"Authorization": "Bear"},
			expected: "",
		},
		{
			name:     "Bearer case insensitive",
			headers:  map[string]string{"Authorization": "BEARER my-tok"},
			expected: "my-tok",
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

// --- getAccessToken ---

func TestGetAccessToken(t *testing.T) {
	b := &gitlabBackend{}

	t.Run("valid", func(t *testing.T) {
		req := &logical.Request{
			Credential: &credential.Credential{
				Type: credential.TypeGitLabAccessToken,
				Data: map[string]string{"access_token": "glpat-xxx"},
			},
		}
		token, err := b.getAccessToken(req)
		assert.NoError(t, err)
		assert.Equal(t, "glpat-xxx", token)
	})

	t.Run("nil credential", func(t *testing.T) {
		req := &logical.Request{}
		_, err := b.getAccessToken(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no credential")
	})

	t.Run("wrong type", func(t *testing.T) {
		req := &logical.Request{
			Credential: &credential.Credential{Type: credential.TypeVaultToken},
		}
		_, err := b.getAccessToken(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported")
	})

	t.Run("missing access_token", func(t *testing.T) {
		req := &logical.Request{
			Credential: &credential.Credential{
				Type: credential.TypeGitLabAccessToken,
				Data: map[string]string{},
			},
		}
		_, err := b.getAccessToken(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing access_token")
	})
}

// --- buildTargetURL ---

func TestBuildTargetURL(t *testing.T) {
	b := &gitlabBackend{gitlabAddress: "https://gitlab.com"}

	tests := []struct {
		name      string
		path      string
		rawQuery  string
		expected  string
		wantErr   bool
	}{
		{"api path", "/v1/gitlab/gateway/api/v4/projects", "", "https://gitlab.com/api/v4/projects", false},
		{"with query", "/v1/gitlab/gateway/api/v4/projects", "per_page=20", "https://gitlab.com/api/v4/projects?per_page=20", false},
		{"gateway root", "/v1/gitlab/gateway", "", "https://gitlab.com/", false},
		{"gateway trailing slash", "/v1/gitlab/gateway/", "", "https://gitlab.com/", false},
		{"no gateway marker", "/v1/gitlab/api/v4/projects", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := b.buildTargetURL(tt.path, tt.rawQuery)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

// --- prepareHeaders ---

func TestPrepareHeaders(t *testing.T) {
	b := &gitlabBackend{}

	t.Run("removes security and hop-by-hop headers, injects bearer", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("PRIVATE-TOKEN", "old-token")
		r.Header.Set("Authorization", "old-auth")
		r.Header.Set("Connection", "keep-alive")
		r.Header.Set("X-Forwarded-For", "1.2.3.4")
		r.Header.Set("Content-Type", "application/json")

		b.prepareHeaders(r, "glpat-new")

		assert.Empty(t, r.Header.Get("PRIVATE-TOKEN"))
		assert.Equal(t, "Bearer glpat-new", r.Header.Get("Authorization"))
		assert.Empty(t, r.Header.Get("Connection"))
		assert.Empty(t, r.Header.Get("X-Forwarded-For"))
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
	})

	t.Run("empty token does not set Authorization", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", "old-auth")

		b.prepareHeaders(r, "")

		assert.Empty(t, r.Header.Get("Authorization"))
	})

	t.Run("Connection-listed headers removed", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Connection", "Custom-Header")
		r.Header.Set("Custom-Header", "val")

		b.prepareHeaders(r, "tok")

		assert.Empty(t, r.Header.Get("Custom-Header"))
	})
}

// --- handleGatewayStreaming ---

func TestHandleGatewayStreaming_NoAddress(t *testing.T) {
	b := &gitlabBackend{
		gitlabAddress: "",
		StreamingBackend: &framework.StreamingBackend{
			Logger:            testLogger(),
			TransparentConfig: &framework.TransparentConfig{},
		},
	}

	httpReq := httptest.NewRequest(http.MethodGet, "/v1/gitlab/gateway/api/v4/projects", nil)
	rr := httptest.NewRecorder()
	req := &logical.Request{
		Path:           "gateway/api/v4/projects",
		HTTPRequest:    httpReq,
		ResponseWriter: rr,
	}

	err := b.handleGatewayStreaming(context.Background(), req, nil)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}

func TestHandleGatewayStreaming_WithMockGitLab(t *testing.T) {
	mockGitLab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer glpat-test", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[{"id":1}]`))
	}))
	defer mockGitLab.Close()

	storage := newInmemStorage()
	ctx := context.Background()
	conf := &logical.BackendConfig{
		StorageView: storage,
		Logger:      testLogger(),
		Config: map[string]any{
			"gitlab_address": mockGitLab.URL,
		},
	}
	b, err := Factory(ctx, conf)
	require.NoError(t, err)
	gb := b.(*gitlabBackend)

	httpReq := httptest.NewRequest(http.MethodGet, "/v1/gitlab/gateway/api/v4/projects", nil)
	rr := httptest.NewRecorder()
	req := &logical.Request{
		Path:           "gateway/api/v4/projects",
		HTTPRequest:    httpReq,
		ResponseWriter: rr,
		Credential: &credential.Credential{
			Type: credential.TypeGitLabAccessToken,
			Data: map[string]string{"access_token": "glpat-test"},
		},
	}

	err = gb.handleGatewayStreaming(context.Background(), req, nil)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestHandleGatewayStreaming_Unauthorized(t *testing.T) {
	mockGitLab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer mockGitLab.Close()

	storage := newInmemStorage()
	conf := &logical.BackendConfig{
		StorageView: storage,
		Logger:      testLogger(),
		Config:      map[string]any{"gitlab_address": mockGitLab.URL},
	}
	b, err := Factory(context.Background(), conf)
	require.NoError(t, err)
	gb := b.(*gitlabBackend)

	httpReq := httptest.NewRequest(http.MethodGet, "/v1/gitlab/gateway/api/v4/projects", nil)
	rr := httptest.NewRecorder()
	req := &logical.Request{
		Path:           "gateway/api/v4/projects",
		HTTPRequest:    httpReq,
		ResponseWriter: rr,
		// No credential
	}

	gb.handleGatewayStreaming(context.Background(), req, nil)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

// --- handleTransparentGatewayStreaming ---

func TestHandleTransparentGatewayStreaming(t *testing.T) {
	mockGitLab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer mockGitLab.Close()

	storage := newInmemStorage()
	conf := &logical.BackendConfig{
		StorageView: storage,
		Logger:      testLogger(),
		Config:      map[string]any{"gitlab_address": mockGitLab.URL},
	}
	b, err := Factory(context.Background(), conf)
	require.NoError(t, err)
	gb := b.(*gitlabBackend)

	httpReq := httptest.NewRequest(http.MethodGet, "/v1/gitlab/role/myrole/gateway/api/v4/projects", nil)
	rr := httptest.NewRecorder()
	req := &logical.Request{
		Path:           "role/myrole/gateway/api/v4/projects",
		HTTPRequest:    httpReq,
		ResponseWriter: rr,
		Credential: &credential.Credential{
			Type: credential.TypeGitLabAccessToken,
			Data: map[string]string{"access_token": "glpat-test"},
		},
	}

	err = gb.handleTransparentGatewayStreaming(context.Background(), req, nil)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rr.Code)
}

// Ensure httputil is used (for InitProxy compatibility)
var _ = (*httputil.ReverseProxy)(nil)
