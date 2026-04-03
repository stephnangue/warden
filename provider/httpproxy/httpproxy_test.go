package httpproxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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
	config := &logger.Config{Level: logger.TraceLevel, Format: logger.DefaultFormat}
	gateConfig := logger.GatedWriterConfig{InitialState: logger.GateOpen}
	gl, _ := logger.NewGatedLogger(config, gateConfig)
	return gl
}

func testSpec() *ProviderSpec {
	transport := NewTransport()
	return &ProviderSpec{
		Name:               "testprovider",
		DefaultURL:         "https://api.test.com",
		URLConfigKey:       "test_url",
		DefaultTimeout:     30 * time.Second,
		ParseStreamBody:    true,
		HelpText:           "Test provider help",
		ExtractCredentials: BearerAPIKeyExtractor,
		Transport:          transport,
		ShutdownTransport:  func() { transport.CloseIdleConnections() },
	}
}

func setupBackend(t *testing.T, spec *ProviderSpec) logical.Backend {
	t.Helper()
	factory := NewFactory(spec)
	b, err := factory(context.Background(), &logical.BackendConfig{
		StorageView: newInmemStorage(),
		Logger:      testLogger(),
	})
	require.NoError(t, err)
	return b
}

func mustNewRequest(t *testing.T, method, target string, headers map[string]string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, target, nil)
	require.NoError(t, err)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

// --- DefaultTokenExtractor tests ---

func TestDefaultTokenExtractor(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		expected string
	}{
		{"X-Warden-Token header", map[string]string{"X-Warden-Token": "warden-token-123"}, "warden-token-123"},
		{"Bearer token", map[string]string{"Authorization": "Bearer my-bearer-token"}, "my-bearer-token"},
		{"X-Warden-Token takes priority", map[string]string{"X-Warden-Token": "warden", "Authorization": "Bearer bearer"}, "warden"},
		{"No token", map[string]string{}, ""},
		{"Non-Bearer auth ignored", map[string]string{"Authorization": "Basic abc"}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := mustNewRequest(t, "GET", "/", tc.headers)
			assert.Equal(t, tc.expected, DefaultTokenExtractor(req))
		})
	}
}

// --- Credential extractor tests ---

func TestBearerAPIKeyExtractor(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		headers, err := BearerAPIKeyExtractor(&logical.Request{
			Credential: &credential.Credential{Type: credential.TypeAPIKey, Data: map[string]string{"api_key": "sk-test"}},
		})
		require.NoError(t, err)
		assert.Equal(t, "Bearer sk-test", headers["Authorization"])
	})
	t.Run("nil credential", func(t *testing.T) {
		_, err := BearerAPIKeyExtractor(&logical.Request{})
		assert.ErrorContains(t, err, "no credential")
	})
	t.Run("wrong type", func(t *testing.T) {
		_, err := BearerAPIKeyExtractor(&logical.Request{Credential: &credential.Credential{Type: "other"}})
		assert.ErrorContains(t, err, "unsupported credential type")
	})
	t.Run("missing api_key", func(t *testing.T) {
		_, err := BearerAPIKeyExtractor(&logical.Request{
			Credential: &credential.Credential{Type: credential.TypeAPIKey, Data: map[string]string{}},
		})
		assert.ErrorContains(t, err, "missing api_key")
	})
}

func TestHeaderAPIKeyExtractor(t *testing.T) {
	extractor := HeaderAPIKeyExtractor("x-api-key")
	t.Run("valid", func(t *testing.T) {
		headers, err := extractor(&logical.Request{
			Credential: &credential.Credential{Type: credential.TypeAPIKey, Data: map[string]string{"api_key": "sk-test"}},
		})
		require.NoError(t, err)
		assert.Equal(t, "sk-test", headers["x-api-key"])
	})
	t.Run("nil credential", func(t *testing.T) {
		_, err := extractor(&logical.Request{})
		assert.Error(t, err)
	})
}

func TestTypedTokenExtractor(t *testing.T) {
	extractor := TypedTokenExtractor(credential.TypeGitHubToken, "token", "Authorization", "token ")
	t.Run("valid", func(t *testing.T) {
		headers, err := extractor(&logical.Request{
			Credential: &credential.Credential{Type: credential.TypeGitHubToken, Data: map[string]string{"token": "ghp_abc"}},
		})
		require.NoError(t, err)
		assert.Equal(t, "token ghp_abc", headers["Authorization"])
	})
	t.Run("wrong type", func(t *testing.T) {
		_, err := extractor(&logical.Request{Credential: &credential.Credential{Type: credential.TypeAPIKey}})
		assert.ErrorContains(t, err, "unsupported credential type")
	})
	t.Run("missing field", func(t *testing.T) {
		_, err := extractor(&logical.Request{
			Credential: &credential.Credential{Type: credential.TypeGitHubToken, Data: map[string]string{}},
		})
		assert.ErrorContains(t, err, "missing token")
	})
	t.Run("no prefix", func(t *testing.T) {
		ext := TypedTokenExtractor("custom", "key", "X-Key", "")
		headers, err := ext(&logical.Request{
			Credential: &credential.Credential{Type: "custom", Data: map[string]string{"key": "val"}},
		})
		require.NoError(t, err)
		assert.Equal(t, "val", headers["X-Key"])
	})
}

func TestMultiFieldAPIKeyExtractor(t *testing.T) {
	extractor := MultiFieldAPIKeyExtractor(
		map[string]string{"api_key": "X-Api-Key"},
		map[string]string{"org_id": "X-Org"},
	)
	t.Run("all fields", func(t *testing.T) {
		headers, err := extractor(&logical.Request{
			Credential: &credential.Credential{Type: credential.TypeAPIKey, Data: map[string]string{"api_key": "key1", "org_id": "org1"}},
		})
		require.NoError(t, err)
		assert.Equal(t, "key1", headers["X-Api-Key"])
		assert.Equal(t, "org1", headers["X-Org"])
	})
	t.Run("optional missing", func(t *testing.T) {
		headers, err := extractor(&logical.Request{
			Credential: &credential.Credential{Type: credential.TypeAPIKey, Data: map[string]string{"api_key": "key1"}},
		})
		require.NoError(t, err)
		assert.Equal(t, "key1", headers["X-Api-Key"])
		assert.Empty(t, headers["X-Org"])
	})
	t.Run("required missing", func(t *testing.T) {
		_, err := extractor(&logical.Request{
			Credential: &credential.Credential{Type: credential.TypeAPIKey, Data: map[string]string{}},
		})
		assert.ErrorContains(t, err, "missing api_key")
	})
}

// --- Config tests ---

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		conf    map[string]any
		wantErr string
	}{
		{"empty is valid", map[string]any{}, ""},
		{"valid URL", map[string]any{"api_url": "https://api.example.com"}, ""},
		{"HTTP rejected", map[string]any{"api_url": "http://api.example.com"}, "https://"},
		{"invalid timeout", map[string]any{"timeout": "bad"}, "invalid timeout"},
		{"negative max_body_size", map[string]any{"max_body_size": -1}, "greater than 0"},
		{"oversized max_body_size", map[string]any{"max_body_size": 200000000}, "100MB"},
		{"valid string timeout", map[string]any{"timeout": "30s"}, ""},
		{"valid int timeout", map[string]any{"timeout": 30}, ""},
		{"valid float timeout", map[string]any{"timeout": 30.0}, ""},
		{"negative float timeout", map[string]any{"timeout": -1.0}, "greater than 0"},
		{"bad timeout type", map[string]any{"timeout": true}, "duration string"},
		{"auto_auth_path not string", map[string]any{"auto_auth_path": 123}, "must be a string"},
		{"default_role not string", map[string]any{"default_role": 123}, "must be a string"},
		{"max_body_size bad type", map[string]any{"max_body_size": true}, "must be an integer"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateConfig(tc.conf, "api_url")
			if tc.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, tc.wantErr)
			}
		})
	}
}

func TestValidateURL(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		wantErr bool
	}{
		{"empty is valid", "", false},
		{"valid HTTPS", "https://api.example.com", false},
		{"HTTP rejected", "http://api.example.com", true},
		{"no scheme", "api.example.com", true},
		{"no host", "https://", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateURL(tc.addr, "api_url")
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestParseConfig(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		c := ParseConfig(map[string]any{}, "api_url", "https://default.com", 30*time.Second)
		assert.Equal(t, "https://default.com", c.ProviderURL)
		assert.Equal(t, framework.DefaultMaxBodySize, c.MaxBodySize)
		assert.Equal(t, 30*time.Second, c.Timeout)
	})
	t.Run("custom values", func(t *testing.T) {
		c := ParseConfig(map[string]any{"api_url": "https://custom.com", "timeout": "60s"}, "api_url", "https://default.com", 30*time.Second)
		assert.Equal(t, "https://custom.com", c.ProviderURL)
		assert.Equal(t, 60*time.Second, c.Timeout)
	})
	t.Run("integer timeout", func(t *testing.T) {
		c := ParseConfig(map[string]any{"timeout": 45}, "u", "https://d.com", 30*time.Second)
		assert.Equal(t, 45*time.Second, c.Timeout)
	})
	t.Run("float timeout", func(t *testing.T) {
		c := ParseConfig(map[string]any{"timeout": 45.0}, "u", "https://d.com", 30*time.Second)
		assert.Equal(t, 45*time.Second, c.Timeout)
	})
	t.Run("auth settings", func(t *testing.T) {
		c := ParseConfig(map[string]any{"auto_auth_path": "auth/jwt/", "default_role": "reader"}, "u", "https://d.com", 30*time.Second)
		assert.Equal(t, "auth/jwt/", c.AutoAuthPath)
		assert.Equal(t, "reader", c.DefaultAuthRole)
	})
}

// --- Transport tests ---

func TestNewTransport(t *testing.T) {
	transport := NewTransport()
	assert.NotNil(t, transport)
	assert.Equal(t, 100, transport.MaxIdleConns)
	assert.Equal(t, 50, transport.MaxIdleConnsPerHost)
	assert.True(t, transport.ForceAttemptHTTP2)
	assert.Equal(t, 90*time.Second, transport.IdleConnTimeout)
}

func TestShutdownTransport(t *testing.T) {
	transport := NewTransport()
	cancel := StartCleanup(transport)
	ShutdownTransport(transport, cancel)
}

// --- NewFactory tests ---

func TestNewFactory(t *testing.T) {
	spec := testSpec()
	b := setupBackend(t, spec)
	assert.Equal(t, "testprovider", b.Type())
	assert.Equal(t, logical.ClassProvider, b.Class())
}

func TestNewFactory_WithConfig(t *testing.T) {
	spec := testSpec()
	factory := NewFactory(spec)
	b, err := factory(context.Background(), &logical.BackendConfig{
		StorageView: newInmemStorage(),
		Logger:      testLogger(),
		Config: map[string]any{
			"test_url":       "https://custom.test.com",
			"timeout":        "60s",
			"auto_auth_path": "auth/jwt/",
			"default_role":   "reader",
		},
	})
	require.NoError(t, err)
	pb := b.(*proxyBackend)
	assert.Equal(t, "https://custom.test.com", pb.providerURL)
	assert.Equal(t, 60*time.Second, pb.Timeout)
}

func TestNewFactory_InvalidConfig(t *testing.T) {
	spec := testSpec()
	factory := NewFactory(spec)
	_, err := factory(context.Background(), &logical.BackendConfig{
		StorageView: newInmemStorage(),
		Logger:      testLogger(),
		Config:      map[string]any{"test_url": "http://insecure.com"},
	})
	assert.ErrorContains(t, err, "https://")
}

func TestNewFactory_ValidateExtraConfig(t *testing.T) {
	spec := testSpec()
	spec.ValidateExtraConfig = func(conf map[string]any) error {
		if _, ok := conf["required_field"]; !ok {
			return assert.AnError
		}
		return nil
	}
	factory := NewFactory(spec)
	_, err := factory(context.Background(), &logical.BackendConfig{
		StorageView: newInmemStorage(),
		Logger:      testLogger(),
		Config:      map[string]any{"test_url": "https://ok.com"},
	})
	assert.Error(t, err)
}

func TestNewFactory_CustomTokenExtractor(t *testing.T) {
	spec := testSpec()
	spec.ExtractToken = func(r *http.Request) string {
		return r.Header.Get("X-Custom-Token")
	}
	b := setupBackend(t, spec)
	pb := b.(*proxyBackend)
	assert.NotNil(t, pb.StreamingBackend.Backend.TokenExtractor)
}

func TestNewFactory_OnInitialize(t *testing.T) {
	spec := testSpec()
	spec.OnInitialize = func(config map[string]any, state map[string]any) map[string]any {
		if v, ok := config["extra_field"].(string); ok {
			state["extra_field"] = v
		}
		return state
	}
	factory := NewFactory(spec)
	b, err := factory(context.Background(), &logical.BackendConfig{
		StorageView: newInmemStorage(),
		Logger:      testLogger(),
		Config:      map[string]any{"test_url": "https://ok.com", "extra_field": "hello", "auto_auth_path": "auth/jwt/"},
	})
	require.NoError(t, err)
	pb := b.(*proxyBackend)
	assert.Equal(t, "hello", pb.extraState["extra_field"])
}

func TestNewFactory_ShutdownHook(t *testing.T) {
	spec := testSpec()
	var hookCalled bool
	factory := NewFactory(spec)
	_, err := factory(context.Background(), &logical.BackendConfig{
		StorageView: newInmemStorage(),
		Logger:      testLogger(),
		RegisterShutdownHook: func(name string, fn func()) {
			hookCalled = true
			assert.Equal(t, "testprovider-transport", name)
		},
	})
	require.NoError(t, err)
	assert.True(t, hookCalled)
}

// --- Initialize tests ---

func TestInitialize_NoStorage(t *testing.T) {
	spec := testSpec()
	factory := NewFactory(spec)
	b, err := factory(context.Background(), &logical.BackendConfig{
		Logger: testLogger(),
	})
	require.NoError(t, err)
	pb := b.(*proxyBackend)
	pb.StorageView = nil
	assert.NoError(t, pb.Initialize(context.Background()))
}

func TestInitialize_EmptyStorage(t *testing.T) {
	spec := testSpec()
	storage := newInmemStorage()
	b := setupBackend(t, spec)
	pb := b.(*proxyBackend)
	pb.StorageView = storage

	require.NoError(t, pb.Initialize(context.Background()))

	// Should have persisted defaults
	entry, err := storage.Get(context.Background(), "config")
	require.NoError(t, err)
	assert.NotNil(t, entry)
}

func TestInitialize_ExistingConfig(t *testing.T) {
	spec := testSpec()
	storage := newInmemStorage()
	entry, _ := sdklogical.StorageEntryJSON("config", map[string]any{
		"test_url":       "https://saved.test.com",
		"max_body_size":  float64(5242880),
		"timeout":        "45s",
		"auto_auth_path": "auth/cert/",
		"default_role":   "admin",
	})
	_ = storage.Put(context.Background(), entry)

	// Create backend with this pre-populated storage
	factory := NewFactory(spec)
	b, err := factory(context.Background(), &logical.BackendConfig{
		StorageView: storage,
		Logger:      testLogger(),
	})
	require.NoError(t, err)
	pb := b.(*proxyBackend)

	require.NoError(t, pb.Initialize(context.Background()))
	assert.Equal(t, "https://saved.test.com", pb.providerURL)
	assert.Equal(t, int64(5242880), pb.MaxBodySize)
	assert.Equal(t, 45*time.Second, pb.Timeout)
	assert.Equal(t, "auth/cert/", pb.TransparentConfig.AutoAuthPath)
	assert.Equal(t, "admin", pb.TransparentConfig.DefaultAuthRole)
}

func TestInitialize_WithExtraState(t *testing.T) {
	spec := testSpec()
	spec.OnInitialize = func(config map[string]any, state map[string]any) map[string]any {
		if v, ok := config["version"].(string); ok {
			state["version"] = v
		}
		return state
	}
	spec.OnConfigRead = func(state map[string]any) map[string]any {
		return map[string]any{"version": state["version"]}
	}

	storage := newInmemStorage()
	entry, _ := sdklogical.StorageEntryJSON("config", map[string]any{
		"test_url": "https://saved.com",
		"timeout":  "30s",
		"version":  "v2",
	})
	_ = storage.Put(context.Background(), entry)

	b := setupBackend(t, spec)
	pb := b.(*proxyBackend)
	pb.StorageView = storage

	require.NoError(t, pb.Initialize(context.Background()))
	assert.Equal(t, "v2", pb.extraState["version"])
}

// --- SensitiveConfigFields tests ---

func TestSensitiveConfigFields(t *testing.T) {
	b := setupBackend(t, testSpec())
	type sf interface{ SensitiveConfigFields() []string }
	assert.Empty(t, b.(sf).SensitiveConfigFields())
}

// --- Config CRUD tests ---

func TestConfigRead(t *testing.T) {
	b := setupBackend(t, testSpec())
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "https://api.test.com", resp.Data["test_url"])
	assert.Equal(t, framework.DefaultMaxBodySize, resp.Data["max_body_size"])
	assert.Equal(t, "30s", resp.Data["timeout"])
}

func TestConfigRead_WithExtraFields(t *testing.T) {
	spec := testSpec()
	spec.OnConfigRead = func(state map[string]any) map[string]any {
		return map[string]any{"version": "v1"}
	}
	b := setupBackend(t, spec)
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
	})
	require.NoError(t, err)
	assert.Equal(t, "v1", resp.Data["version"])
}

func TestConfigWrite(t *testing.T) {
	b := setupBackend(t, testSpec())
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Data: map[string]any{
			"test_url":       "https://custom.test.com",
			"timeout":        120,
			"auto_auth_path": "auth/jwt/",
			"default_role":   "reader",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Read back
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
	})
	require.NoError(t, err)
	assert.Equal(t, "https://custom.test.com", resp.Data["test_url"])
	assert.Equal(t, "auth/jwt/", resp.Data["auto_auth_path"])
}

func TestConfigWrite_InvalidURL(t *testing.T) {
	b := setupBackend(t, testSpec())
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Data: map[string]any{
			"test_url":       "http://insecure.com",
			"auto_auth_path": "auth/jwt/",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestConfigWrite_MissingAutoAuthPath(t *testing.T) {
	b := setupBackend(t, testSpec())
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Data: map[string]any{
			"test_url": "https://ok.com",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestConfigWrite_WithExtraFields(t *testing.T) {
	spec := testSpec()
	spec.ExtraConfigFields = map[string]*framework.FieldSchema{
		"version": {Type: framework.TypeString, Default: "v1"},
	}
	spec.OnConfigWrite = func(d *framework.FieldData, state map[string]any) (map[string]any, error) {
		if val, ok := d.GetOk("version"); ok {
			state["version"] = val.(string)
		}
		return state, nil
	}
	spec.OnConfigRead = func(state map[string]any) map[string]any {
		return map[string]any{"version": state["version"]}
	}

	b := setupBackend(t, spec)
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Data: map[string]any{
			"auto_auth_path": "auth/jwt/",
			"version":        "v2",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	resp, _ = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
	})
	assert.Equal(t, "v2", resp.Data["version"])
}

// --- Gateway proxy tests ---

func TestHandleGateway_Success(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Received-Path", r.URL.Path)
		w.Header().Set("X-Received-Auth", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	spec := testSpec()
	b := setupBackend(t, spec)
	pb := b.(*proxyBackend)
	pb.providerURL = upstream.URL
	pb.StreamingBackend.InitProxy(upstream.Client().Transport)

	rec := httptest.NewRecorder()
	httpReq := httptest.NewRequest("POST", "/test/gateway/v1/endpoint", strings.NewReader(`{"data":"test"}`))
	httpReq.URL, _ = url.Parse(upstream.URL + "/test/gateway/v1/endpoint")

	req := &logical.Request{
		HTTPRequest:    httpReq,
		ResponseWriter: rec,
		Credential:     &credential.Credential{Type: credential.TypeAPIKey, Data: map[string]string{"api_key": "sk-test"}},
	}

	pb.handleGateway(context.Background(), req)
	assert.Equal(t, http.StatusOK, rec.Code)
	body, _ := io.ReadAll(rec.Result().Body)
	assert.Contains(t, string(body), `"ok":true`)
}

func TestHandleGateway_NoCredential(t *testing.T) {
	spec := testSpec()
	b := setupBackend(t, spec)
	pb := b.(*proxyBackend)

	rec := httptest.NewRecorder()
	httpReq := httptest.NewRequest("POST", "/test/gateway/v1/endpoint", nil)

	pb.handleGateway(context.Background(), &logical.Request{
		HTTPRequest:    httpReq,
		ResponseWriter: rec,
	})
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestHandleGateway_InvalidGatewayPath(t *testing.T) {
	spec := testSpec()
	b := setupBackend(t, spec)
	pb := b.(*proxyBackend)

	rec := httptest.NewRecorder()
	httpReq := httptest.NewRequest("POST", "/test/v1/endpoint", nil)

	pb.handleGateway(context.Background(), &logical.Request{
		HTTPRequest:    httpReq,
		ResponseWriter: rec,
		Credential:     &credential.Credential{Type: credential.TypeAPIKey, Data: map[string]string{"api_key": "sk-test"}},
	})
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestHandleGatewayStreaming(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	spec := testSpec()
	b := setupBackend(t, spec)
	pb := b.(*proxyBackend)
	pb.providerURL = upstream.URL
	pb.StreamingBackend.InitProxy(upstream.Client().Transport)

	rec := httptest.NewRecorder()
	httpReq := httptest.NewRequest("POST", "/test/gateway/v1/chat", nil)
	httpReq.URL, _ = url.Parse(upstream.URL + "/test/gateway/v1/chat")

	err := pb.handleGatewayStreaming(context.Background(), &logical.Request{
		HTTPRequest:    httpReq,
		ResponseWriter: rec,
		Credential:     &credential.Credential{Type: credential.TypeAPIKey, Data: map[string]string{"api_key": "sk-test"}},
	}, nil)
	assert.NoError(t, err)
}

func TestHandleTransparentGatewayStreaming(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	spec := testSpec()
	b := setupBackend(t, spec)
	pb := b.(*proxyBackend)
	pb.providerURL = upstream.URL
	pb.StreamingBackend.InitProxy(upstream.Client().Transport)

	rec := httptest.NewRecorder()
	httpReq := httptest.NewRequest("POST", "/test/role/reader/gateway/v1/chat", nil)
	httpReq.URL, _ = url.Parse(upstream.URL + "/test/role/reader/gateway/v1/chat")

	req := &logical.Request{
		HTTPRequest:    httpReq,
		ResponseWriter: rec,
		Path:           "role/reader/gateway/v1/chat",
		Credential:     &credential.Credential{Type: credential.TypeAPIKey, Data: map[string]string{"api_key": "sk-test"}},
	}

	err := pb.handleTransparentGatewayStreaming(context.Background(), req, nil)
	assert.NoError(t, err)
	assert.Contains(t, req.Path, "gateway")
	assert.NotContains(t, req.Path, "role/reader")
}

// --- buildTargetURL tests ---

func TestBuildTargetURL(t *testing.T) {
	pb := &proxyBackend{providerURL: "https://api.test.com"}
	tests := []struct {
		name     string
		path     string
		query    string
		expected string
		wantErr  bool
	}{
		{"standard path", "/test/gateway/v1/endpoint", "", "https://api.test.com/v1/endpoint", false},
		{"with query", "/test/gateway/v1/endpoint", "page=1", "https://api.test.com/v1/endpoint?page=1", false},
		{"bare gateway", "/test/gateway", "", "https://api.test.com/", false},
		{"trailing slash", "/test/gateway/", "", "https://api.test.com/", false},
		{"no gateway marker", "/test/v1/endpoint", "", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := pb.buildTargetURL(tc.path, tc.query)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

// --- prepareHeaders tests ---

func TestPrepareHeaders(t *testing.T) {
	spec := testSpec()
	spec.ExtraHeadersToRemove = []string{"X-Custom-Remove"}
	spec.DefaultHeaders = map[string]string{"X-Default": "val"}
	spec.DefaultAccept = "text/plain"
	spec.UserAgent = "test-agent"

	b := setupBackend(t, spec)
	pb := b.(*proxyBackend)

	t.Run("removes security headers and injects credentials", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "https://api.test.com/v1/chat", nil)
		req.Header.Set("Authorization", "Bearer warden-token")
		req.Header.Set("X-Warden-Token", "warden-token")
		req.Header.Set("X-Custom-Remove", "should-go")
		req.Header.Set("X-Keep", "keep-me")

		pb.prepareHeaders(req, map[string]string{"Authorization": "Bearer real-key"})

		assert.Equal(t, "Bearer real-key", req.Header.Get("Authorization"))
		assert.Empty(t, req.Header.Get("X-Warden-Token"))
		assert.Empty(t, req.Header.Get("X-Custom-Remove"))
		assert.Equal(t, "keep-me", req.Header.Get("X-Keep"))
	})

	t.Run("sets default and static headers", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "https://api.test.com/v1/chat", nil)
		pb.prepareHeaders(req, map[string]string{"Authorization": "Bearer key"})

		assert.Equal(t, "val", req.Header.Get("X-Default"))
		assert.Equal(t, "text/plain", req.Header.Get("Accept"))
		assert.Equal(t, "test-agent", req.Header.Get("User-Agent"))
	})

	t.Run("preserves client-set Accept", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "https://api.test.com/v1/chat", nil)
		req.Header.Set("Accept", "text/event-stream")
		pb.prepareHeaders(req, map[string]string{})
		assert.Equal(t, "text/event-stream", req.Header.Get("Accept"))
	})

	t.Run("removes hop-by-hop headers", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "https://api.test.com/v1/chat", nil)
		req.Header.Set("Connection", "keep-alive")
		req.Header.Set("Transfer-Encoding", "chunked")
		req.Header.Set("Proxy-Authorization", "Basic abc")
		pb.prepareHeaders(req, map[string]string{})
		assert.Empty(t, req.Header.Get("Connection"))
		assert.Empty(t, req.Header.Get("Transfer-Encoding"))
		assert.Empty(t, req.Header.Get("Proxy-Authorization"))
	})

	t.Run("removes Connection-listed headers", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "https://api.test.com/v1/chat", nil)
		req.Header.Set("Connection", "X-Custom-Hop")
		req.Header.Set("X-Custom-Hop", "should-be-removed")
		pb.prepareHeaders(req, map[string]string{})
		assert.Empty(t, req.Header.Get("X-Custom-Hop"))
	})

	t.Run("removes proxy headers", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "https://api.test.com/v1/chat", nil)
		req.Header.Set("X-Forwarded-For", "10.0.0.1")
		req.Header.Set("X-Real-Ip", "10.0.0.1")
		req.Header.Set("Forwarded", "for=10.0.0.1")
		pb.prepareHeaders(req, map[string]string{})
		assert.Empty(t, req.Header.Get("X-Forwarded-For"))
		assert.Empty(t, req.Header.Get("X-Real-Ip"))
		assert.Empty(t, req.Header.Get("Forwarded"))
	})
}

func TestPrepareHeaders_DynamicHeaders(t *testing.T) {
	spec := testSpec()
	spec.DynamicHeaders = func(state map[string]any) map[string]string {
		ver, _ := state["version"].(string)
		if ver == "" {
			ver = "v1"
		}
		return map[string]string{"X-Api-Version": ver}
	}

	b := setupBackend(t, spec)
	pb := b.(*proxyBackend)
	pb.extraState["version"] = "v2"

	req, _ := http.NewRequest("POST", "https://api.test.com/v1/chat", nil)
	pb.prepareHeaders(req, map[string]string{})
	assert.Equal(t, "v2", req.Header.Get("X-Api-Version"))
}

func TestPrepareHeaders_DynamicHeaders_NotOverrideClient(t *testing.T) {
	spec := testSpec()
	spec.DynamicHeaders = func(state map[string]any) map[string]string {
		return map[string]string{"X-Api-Version": "v2"}
	}

	b := setupBackend(t, spec)
	pb := b.(*proxyBackend)

	req, _ := http.NewRequest("POST", "https://api.test.com/v1/chat", nil)
	req.Header.Set("X-Api-Version", "client-v1")
	pb.prepareHeaders(req, map[string]string{})
	assert.Equal(t, "client-v1", req.Header.Get("X-Api-Version"))
}

func TestPrepareHeaders_DefaultUserAgent(t *testing.T) {
	spec := testSpec()
	spec.UserAgent = "" // use default

	b := setupBackend(t, spec)
	pb := b.(*proxyBackend)

	req, _ := http.NewRequest("POST", "https://api.test.com/v1/chat", nil)
	pb.prepareHeaders(req, map[string]string{})
	assert.Equal(t, "warden-testprovider-proxy", req.Header.Get("User-Agent"))
}
