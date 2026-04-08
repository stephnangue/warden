package vault

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
	vb := b.(*vaultBackend)
	assert.Equal(t, "vault", vb.Type())
	assert.Equal(t, logical.ClassProvider, vb.Class())
	assert.Equal(t, framework.DefaultMaxBodySize, vb.MaxBodySize)
	assert.Equal(t, framework.DefaultTimeout, vb.Timeout)
}

func TestFactory_WithConfig(t *testing.T) {
	storage := newInmemStorage()
	ctx := context.Background()
	conf := &logical.BackendConfig{
		StorageView: storage,
		Logger:      testLogger(),
		Config: map[string]any{
			"vault_address":   "https://vault.example.com:8200",
			"max_body_size":   int64(5242880),
			"timeout":         "60s",
			"tls_skip_verify": true,
		},
	}
	b, err := Factory(ctx, conf)
	require.NoError(t, err)
	vb := b.(*vaultBackend)
	assert.Equal(t, "https://vault.example.com:8200", vb.vaultAddress)
	assert.Equal(t, int64(5242880), vb.MaxBodySize)
	assert.Equal(t, 60*time.Second, vb.Timeout)
	assert.True(t, vb.tlsSkipVerify)
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
			assert.Equal(t, "vault-transport", name)
		},
	}
	_, err := Factory(ctx, conf)
	require.NoError(t, err)
	assert.True(t, hookCalled)
}

// --- Initialize tests ---

func TestInitialize_NoStorage(t *testing.T) {
	b := &vaultBackend{
		StreamingBackend: &framework.StreamingBackend{},
	}
	err := b.Initialize(context.Background())
	assert.NoError(t, err)
}

func TestInitialize_EmptyStorage(t *testing.T) {
	storage := newInmemStorage()
	b := &vaultBackend{
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
		"vault_address":   "https://saved.vault.com:8200",
		"max_body_size":   int64(5242880),
		"timeout":         "60s",
		"tls_skip_verify": false,
		"auto_auth_path":  "auth/jwt/",
		"default_role":    "reader",
	})
	_ = storage.Put(context.Background(), entry)

	b := &vaultBackend{
		StreamingBackend: &framework.StreamingBackend{
			StorageView:       storage,
			TransparentConfig: &framework.TransparentConfig{},
			Proxy:             &httputil.ReverseProxy{Transport: sharedTransport},
		},
	}

	err := b.Initialize(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "https://saved.vault.com:8200", b.vaultAddress)
	assert.Equal(t, int64(5242880), b.MaxBodySize)
	assert.Equal(t, 60*time.Second, b.Timeout)
}

func TestInitialize_TLSSkipVerify(t *testing.T) {
	storage := newInmemStorage()
	entry, _ := sdklogical.StorageEntryJSON("config", map[string]any{
		"vault_address":   "https://vault.com:8200",
		"tls_skip_verify": true,
		"timeout":         "30s",
	})
	_ = storage.Put(context.Background(), entry)

	b := &vaultBackend{
		StreamingBackend: &framework.StreamingBackend{
			StorageView:       storage,
			TransparentConfig: &framework.TransparentConfig{},
			Proxy:             &httputil.ReverseProxy{Transport: sharedTransport},
		},
	}

	err := b.Initialize(context.Background())
	require.NoError(t, err)
	assert.True(t, b.tlsSkipVerify)
	// Transport should be updated
	assert.NotEqual(t, sharedTransport, b.Proxy.Transport)
}

// --- SensitiveConfigFields ---

func TestSensitiveConfigFields(t *testing.T) {
	b := &vaultBackend{}
	fields := b.SensitiveConfigFields()
	assert.Empty(t, fields)
}

// --- paths ---

func TestPaths(t *testing.T) {
	b := &vaultBackend{}
	paths := b.paths()
	require.Len(t, paths, 1)
	assert.Equal(t, "config", paths[0].Pattern)
}

// --- ShutdownHTTPTransport ---

func TestShutdownHTTPTransport(t *testing.T) {
	// Should not panic
	ShutdownHTTPTransport()
}

// --- validateVaultAddress ---

func TestValidateVaultAddress(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		wantErr bool
		errMsg  string
	}{
		{"valid https", "https://vault.example.com:8200", false, ""},
		{"valid http", "http://localhost:8200", false, ""},
		{"empty", "", true, "required"},
		{"no scheme", "vault.example.com", true, "scheme"},
		{"ftp scheme", "ftp://vault.example.com", true, "scheme"},
		{"no host", "https://", true, "host"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateVaultAddress(tt.addr)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// --- handleConfigWrite additional coverage ---

func TestHandleConfigWrite_InvalidAddress(t *testing.T) {
	b := &vaultBackend{
		StreamingBackend: &framework.StreamingBackend{
			TransparentConfig: &framework.TransparentConfig{},
		},
	}
	path := b.pathConfig()
	fd := &framework.FieldData{
		Raw: map[string]interface{}{
			"vault_address":  "ftp://bad-scheme",
			"auto_auth_path": "auth/jwt/",
		},
		Schema: path.Fields,
	}

	resp, err := b.handleConfigWrite(context.Background(), nil, fd)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestHandleConfigWrite_MissingAutoAuthPath(t *testing.T) {
	b := &vaultBackend{
		StreamingBackend: &framework.StreamingBackend{
			TransparentConfig: &framework.TransparentConfig{},
		},
	}
	path := b.pathConfig()
	fd := &framework.FieldData{
		Raw: map[string]interface{}{
			"vault_address": "https://vault.example.com:8200",
		},
		Schema: path.Fields,
	}

	resp, err := b.handleConfigWrite(context.Background(), nil, fd)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestHandleConfigWrite_PersistsToStorage(t *testing.T) {
	storage := newInmemStorage()
	b := &vaultBackend{
		StreamingBackend: &framework.StreamingBackend{
			StorageView:       storage,
			TransparentConfig: &framework.TransparentConfig{},
		},
	}
	path := b.pathConfig()
	fd := &framework.FieldData{
		Raw: map[string]interface{}{
			"vault_address":  "https://vault.example.com:8200",
			"auto_auth_path": "auth/jwt/",
			"default_role":   "admin",
		},
		Schema: path.Fields,
	}

	resp, err := b.handleConfigWrite(context.Background(), nil, fd)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	entry, err := storage.Get(context.Background(), "config")
	require.NoError(t, err)
	require.NotNil(t, entry)
}

// --- handleGatewayStreaming / handleTransparentGatewayStreaming ---

func TestHandleGatewayStreaming_NoAddress(t *testing.T) {
	b := &vaultBackend{
		vaultAddress: "",
		StreamingBackend: &framework.StreamingBackend{
			Logger:            createTestLogger(),
			TransparentConfig: &framework.TransparentConfig{},
		},
	}

	httpReq := httptest.NewRequest(http.MethodGet, "/v1/vault/gateway/sys/health", nil)
	rr := httptest.NewRecorder()
	req := &logical.Request{
		Path:           "gateway/sys/health",
		HTTPRequest:    httpReq,
		ResponseWriter: rr,
	}

	err := b.handleGatewayStreaming(context.Background(), req, nil)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}

func TestHandleGatewayStreaming_WithMockVault(t *testing.T) {
	mockVault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"initialized":true}`))
	}))
	defer mockVault.Close()

	storage := newInmemStorage()
	ctx := context.Background()
	conf := &logical.BackendConfig{
		StorageView: storage,
		Logger:      testLogger(),
		Config: map[string]any{
			"vault_address": mockVault.URL,
		},
	}
	b, err := Factory(ctx, conf)
	require.NoError(t, err)
	vb := b.(*vaultBackend)

	httpReq := httptest.NewRequest(http.MethodGet, "/v1/vault/gateway/sys/health", nil)
	rr := httptest.NewRecorder()
	req := &logical.Request{
		Path:           "gateway/sys/health",
		HTTPRequest:    httpReq,
		ResponseWriter: rr,
		Credential: &credential.Credential{
			Type: credential.TypeVaultToken,
			Data: map[string]string{"token": "hvs.test"},
		},
	}

	err = vb.handleGatewayStreaming(context.Background(), req, nil)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestHandleTransparentGatewayStreaming(t *testing.T) {
	mockVault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer mockVault.Close()

	storage := newInmemStorage()
	ctx := context.Background()
	conf := &logical.BackendConfig{
		StorageView: storage,
		Logger:      testLogger(),
		Config: map[string]any{
			"vault_address": mockVault.URL,
		},
	}
	b, err := Factory(ctx, conf)
	require.NoError(t, err)
	vb := b.(*vaultBackend)

	httpReq := httptest.NewRequest(http.MethodGet, "/v1/vault/role/myrole/gateway/sys/health", nil)
	rr := httptest.NewRecorder()
	req := &logical.Request{
		Path:           "role/myrole/gateway/sys/health",
		HTTPRequest:    httpReq,
		ResponseWriter: rr,
		Credential: &credential.Credential{
			Type: credential.TypeVaultToken,
			Data: map[string]string{"token": "hvs.test"},
		},
	}

	err = vb.handleTransparentGatewayStreaming(context.Background(), req, nil)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rr.Code)
}
