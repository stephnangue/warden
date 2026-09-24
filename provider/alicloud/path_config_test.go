package alicloud

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
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

func setupBackend(t *testing.T) *alicloudBackend {
	t.Helper()
	storage := newInmemStorage()
	ctx := context.Background()
	conf := &logical.BackendConfig{
		StorageView: storage,
		Logger:      testLogger(),
	}
	b, err := Factory(ctx, conf)
	require.NoError(t, err)
	return b.(*alicloudBackend)
}

func makeFieldData(path *framework.Path, raw map[string]interface{}) *framework.FieldData {
	return &framework.FieldData{Raw: raw, Schema: path.Fields}
}

// --- Factory tests ---

func TestFactory(t *testing.T) {
	b := setupBackend(t)
	assert.Equal(t, "alicloud", b.Type())
	assert.Equal(t, logical.ClassProvider, b.Class())
	assert.Equal(t, DefaultTimeout, b.Timeout())
	assert.Equal(t, framework.DefaultMaxBodySize, b.MaxBodySize())
}

func TestFactory_WithConfig(t *testing.T) {
	storage := newInmemStorage()
	conf := &logical.BackendConfig{
		StorageView: storage,
		Logger:      testLogger(),
		Config: map[string]any{
			"timeout":        "60s",
			"auto_auth_path": "auth/jwt/",
			"default_role":   "reader",
		},
	}
	b, err := Factory(context.Background(), conf)
	require.NoError(t, err)
	ab := b.(*alicloudBackend)
	assert.Equal(t, 60.0, ab.Timeout().Seconds())
	tc := ab.TransparentConfig()
	assert.Equal(t, "auth/jwt/", tc.AutoAuthPath)
	assert.Equal(t, "reader", tc.DefaultAuthRole)
}

func TestFactory_InvalidConfig(t *testing.T) {
	conf := &logical.BackendConfig{
		StorageView: newInmemStorage(),
		Logger:      testLogger(),
		Config:      map[string]any{"unknown_key": "value"},
	}
	_, err := Factory(context.Background(), conf)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown configuration key")
}

// --- Initialize tests ---

func TestInitialize_EmptyStorage(t *testing.T) {
	b := setupBackend(t)
	storage := newInmemStorage()
	b.StorageView = storage

	err := b.Initialize(context.Background())
	require.NoError(t, err)

	entry, err := storage.Get(context.Background(), "config")
	require.NoError(t, err)
	require.NotNil(t, entry, "defaults should be persisted on first run")
}

func TestInitialize_ExistingConfig(t *testing.T) {
	storage := newInmemStorage()
	entry, _ := sdklogical.StorageEntryJSON("config", map[string]any{
		"max_body_size":  int64(5242880),
		"timeout":        "45s",
		"auto_auth_path": "auth/cert/",
		"default_role":   "admin",
	})
	_ = storage.Put(context.Background(), entry)

	b := setupBackend(t)
	b.StorageView = storage

	err := b.Initialize(context.Background())
	require.NoError(t, err)

	assert.Equal(t, int64(5242880), b.MaxBodySize())
	assert.Equal(t, 45.0, b.Timeout().Seconds())
	tc := b.TransparentConfig()
	assert.Equal(t, "auth/cert/", tc.AutoAuthPath)
	assert.Equal(t, "admin", tc.DefaultAuthRole)
}

// --- Config CRUD tests ---

func TestConfigRead(t *testing.T) {
	b := setupBackend(t)

	resp, err := b.handleConfigRead(context.Background(), nil, nil)
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, framework.DefaultMaxBodySize, resp.Data["max_body_size"])
	assert.Equal(t, DefaultTimeout.String(), resp.Data["timeout"])
}

func TestConfigWrite(t *testing.T) {
	b := setupBackend(t)
	ctx := context.Background()
	path := b.pathConfig()

	t.Run("update config", func(t *testing.T) {
		d := makeFieldData(path, map[string]interface{}{
			"timeout":        120,
			"auto_auth_path": "auth/jwt/",
			"default_role":   "reader",
		})
		resp, err := b.handleConfigWrite(ctx, &logical.Request{}, d)
		require.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)
	})

	t.Run("read back updated config", func(t *testing.T) {
		resp, err := b.handleConfigRead(ctx, nil, nil)
		require.NoError(t, err)
		assert.Equal(t, "auth/jwt/", resp.Data["auto_auth_path"])
		assert.Equal(t, "reader", resp.Data["default_role"])
	})

	t.Run("missing auto_auth_path rejected", func(t *testing.T) {
		b.StreamingBackend.SetTransparentConfig(&framework.TransparentConfig{})
		d := makeFieldData(path, map[string]interface{}{})
		resp, err := b.handleConfigWrite(ctx, &logical.Request{}, d)
		require.NoError(t, err)
		assert.Equal(t, 400, resp.StatusCode)
	})

	t.Run("invalid ca_data rejected", func(t *testing.T) {
		b.StreamingBackend.SetTransparentConfig(&framework.TransparentConfig{AutoAuthPath: "auth/jwt/"})
		d := makeFieldData(path, map[string]interface{}{
			"auto_auth_path": "auth/jwt/",
			"ca_data":        "not-valid-base64-or-pem!!!",
		})
		resp, err := b.handleConfigWrite(ctx, &logical.Request{}, d)
		require.NoError(t, err)
		assert.Equal(t, 400, resp.StatusCode)
	})
}

// --- Misc ---

func TestSensitiveConfigFields(t *testing.T) {
	b := setupBackend(t)
	fields := b.SensitiveConfigFields()
	assert.Contains(t, fields, "ca_data")
}

func TestValidateConfig(t *testing.T) {
	t.Run("allowed keys pass", func(t *testing.T) {
		err := ValidateConfig(map[string]any{
			"max_body_size":  int64(1 << 20),
			"timeout":        "30s",
			"auto_auth_path": "auth/jwt/",
			"default_role":   "r",
		})
		assert.NoError(t, err)
	})

	t.Run("unknown key rejected", func(t *testing.T) {
		err := ValidateConfig(map[string]any{"unknown": "x"})
		assert.Error(t, err)
	})
}

func writeConfig(b *alicloudBackend, raw map[string]interface{}) *logical.Response {
	resp, _ := b.handleConfigWrite(context.Background(), nil, makeFieldData(b.pathConfig(), raw))
	return resp
}

// verifiesTLS reports whether the backend's transport verifies a server's
// certificate: a request to a self-signed server fails verification exactly
// then.
func verifiesTLS(t *testing.T, b *alicloudBackend) bool {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	resp, err := b.Transport().RoundTrip(req)
	if err == nil {
		resp.Body.Close()
	}
	var verifyErr *tls.CertificateVerificationError
	return errors.As(err, &verifyErr)
}

// failingStorage refuses every write.
type failingStorage struct{ *inmemStorage }

func (failingStorage) Put(context.Context, *sdklogical.StorageEntry) error {
	return errors.New("storage unavailable")
}

// A write that cannot be persisted is not applied either: not its limits, its
// domains, its transparent config, nor its transport. Before, all of them
// were live by the time the storage write failed.
func TestConfigWrite_UnpersistedWriteNotApplied(t *testing.T) {
	b := setupBackend(t)
	require.Equal(t, http.StatusOK, writeConfig(b, map[string]interface{}{"auto_auth_path": "auth/jwt/"}).StatusCode)
	require.True(t, verifiesTLS(t, b))
	b.StorageView = failingStorage{newInmemStorage()}

	resp := writeConfig(b, map[string]interface{}{
		"timeout": 99, "tls_skip_verify": true, "proxy_domains": "other.example.com", "auto_auth_path": "auth/other/",
	})
	require.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	assert.Equal(t, DefaultTimeout, b.Timeout())
	assert.Equal(t, "auth/jwt/", b.TransparentConfig().AutoAuthPath)
	assert.NotEqual(t, []string{"other.example.com"}, b.getProxyDomains())
	assert.True(t, verifiesTLS(t, b), "an unpersisted write must not have turned TLS verification off")
}

// Clearing TLS settings goes back to verifying transport. Before, only a
// write that set them rebuilt the transport, so the one built to skip
// verification stayed in use after they were cleared.
func TestConfigWrite_ClearingTLSRestoresVerification(t *testing.T) {
	b := setupBackend(t)
	require.Equal(t, http.StatusOK, writeConfig(b, map[string]interface{}{
		"tls_skip_verify": true, "auto_auth_path": "auth/jwt/",
	}).StatusCode)
	require.False(t, verifiesTLS(t, b))

	require.Equal(t, http.StatusOK, writeConfig(b, map[string]interface{}{"auto_auth_path": "auth/jwt/"}).StatusCode)
	assert.True(t, verifiesTLS(t, b))
}
