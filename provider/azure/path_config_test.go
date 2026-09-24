package azure

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
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

func setupBackend(t *testing.T) *azureBackend {
	t.Helper()
	storage := newInmemStorage()
	ctx := context.Background()
	conf := &logical.BackendConfig{
		StorageView: storage,
		Logger:      testLogger(),
	}
	b, err := Factory(ctx, conf)
	require.NoError(t, err)
	return b.(*azureBackend)
}

func makeFieldData(path *framework.Path, raw map[string]interface{}) *framework.FieldData {
	return &framework.FieldData{
		Raw:    raw,
		Schema: path.Fields,
	}
}

// --- Factory tests ---

func TestFactory(t *testing.T) {
	b := setupBackend(t)
	assert.Equal(t, "azure", b.Type())
	assert.Equal(t, logical.ClassProvider, b.Class())
	assert.Equal(t, framework.DefaultTimeout, b.Timeout())
	assert.Equal(t, framework.DefaultMaxBodySize, b.MaxBodySize())
}

func TestFactory_WithConfig(t *testing.T) {
	storage := newInmemStorage()
	ctx := context.Background()
	conf := &logical.BackendConfig{
		StorageView: storage,
		Logger:      testLogger(),
		Config: map[string]any{
			"timeout":        "60s",
			"auto_auth_path": "auth/jwt/",
			"default_role":   "reader",
		},
	}
	b, err := Factory(ctx, conf)
	require.NoError(t, err)
	ab := b.(*azureBackend)
	assert.Equal(t, 60.0, ab.Timeout().Seconds())
	tc := ab.TransparentConfig()
	assert.Equal(t, "auth/jwt/", tc.AutoAuthPath)
	assert.Equal(t, "reader", tc.DefaultAuthRole)
}

func TestFactory_InvalidConfig(t *testing.T) {
	storage := newInmemStorage()
	ctx := context.Background()
	conf := &logical.BackendConfig{
		StorageView: storage,
		Logger:      testLogger(),
		Config: map[string]any{
			"unknown_key": "value",
		},
	}
	_, err := Factory(ctx, conf)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown configuration key")
}

// --- Initialize tests ---

func TestInitialize_NoStorage(t *testing.T) {
	b := &azureBackend{
		StreamingBackend: &framework.StreamingBackend{},
	}
	err := b.Initialize(context.Background())
	assert.NoError(t, err)
}

func TestInitialize_EmptyStorage(t *testing.T) {
	b := setupBackend(t)
	storage := newInmemStorage()
	b.StorageView = storage

	err := b.Initialize(context.Background())
	require.NoError(t, err)

	// Should have persisted defaults
	entry, err := storage.Get(context.Background(), "config")
	require.NoError(t, err)
	require.NotNil(t, entry)
}

func TestInitialize_ExistingConfig(t *testing.T) {
	storage := newInmemStorage()
	entry, _ := sdklogical.StorageEntryJSON("config", map[string]any{
		"max_body_size":  int64(5242880),
		"timeout":        "30s",
		"auto_auth_path": "auth/cert/",
		"default_role":   "admin",
	})
	_ = storage.Put(context.Background(), entry)

	b := setupBackend(t)
	b.StorageView = storage

	err := b.Initialize(context.Background())
	require.NoError(t, err)

	assert.Equal(t, int64(5242880), b.MaxBodySize())
	assert.Equal(t, 30.0, b.Timeout().Seconds())
	tc := b.TransparentConfig()
	assert.Equal(t, "auth/cert/", tc.AutoAuthPath)
	assert.Equal(t, "admin", tc.DefaultAuthRole)
}

// --- Config CRUD tests ---

func TestConfigRead(t *testing.T) {
	b := setupBackend(t)
	ctx := context.Background()

	resp, err := b.handleConfigRead(ctx, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, framework.DefaultMaxBodySize, resp.Data["max_body_size"])
	assert.Equal(t, framework.DefaultTimeout.String(), resp.Data["timeout"])
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
}

// --- SensitiveConfigFields tests ---

func TestSensitiveConfigFields(t *testing.T) {
	b := setupBackend(t)
	fields := b.SensitiveConfigFields()
	assert.Contains(t, fields, "ca_data")
}

// --- getAzureCredentialInfo tests ---

func TestGetAzureCredentialInfo(t *testing.T) {
	b := setupBackend(t)

	t.Run("nil credential", func(t *testing.T) {
		req := &logical.Request{}
		_, err := b.getAzureCredentialInfo(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no credential")
	})

	t.Run("wrong credential type", func(t *testing.T) {
		req := &logical.Request{
			Credential: &credential.Credential{
				Type: credential.TypeGCPAccessToken,
				Data: map[string]string{"access_token": "tok"},
			},
		}
		_, err := b.getAzureCredentialInfo(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported credential type")
	})

	t.Run("missing access_token", func(t *testing.T) {
		req := &logical.Request{
			Credential: &credential.Credential{
				Type: credential.TypeAzureBearerToken,
				Data: map[string]string{},
			},
		}
		_, err := b.getAzureCredentialInfo(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing access_token")
	})

	t.Run("valid credential", func(t *testing.T) {
		req := &logical.Request{
			Credential: &credential.Credential{
				Type: credential.TypeAzureBearerToken,
				Data: map[string]string{"access_token": "eyJ0eXAiOiJKV1Qi.test-token"},
			},
		}
		info, err := b.getAzureCredentialInfo(req)
		assert.NoError(t, err)
		assert.Equal(t, "eyJ0eXAiOiJKV1Qi.test-token", info.bearerToken)
	})
}

// configuredBackend is a backend running a known configuration, over the
// shared transport, with storage.
func configuredBackend(storage sdklogical.Storage) *azureBackend {
	b := &azureBackend{StreamingBackend: &framework.StreamingBackend{Logger: testLogger()}}
	b.SetMaxBodySize(framework.DefaultMaxBodySize)
	b.SetTimeout(30 * time.Second)
	b.SetTransparentConfig(&framework.TransparentConfig{AutoAuthPath: "auth/jwt/"})
	initTransport()
	b.InitProxy(sharedTransport)
	b.StorageView = storage
	return b
}

func writeConfig(b *azureBackend, raw map[string]interface{}) *logical.Response {
	resp, _ := b.handleConfigWrite(context.Background(), nil,
		&framework.FieldData{Raw: raw, Schema: b.pathConfig().Fields})
	return resp
}

func assertUnchanged(t *testing.T, b *azureBackend) {
	t.Helper()
	skipVerify, caData := b.tlsSettings()
	assert.False(t, skipVerify)
	assert.Empty(t, caData)
	assert.Equal(t, framework.DefaultMaxBodySize, b.MaxBodySize())
	assert.Equal(t, 30*time.Second, b.Timeout())
	assert.Equal(t, "auth/jwt/", b.TransparentConfig().AutoAuthPath)
}

// A rejected write changes nothing — not the limits, not the transparent
// config, and not the transport, which is proved by what it does. Before, the
// write below turned TLS verification off and only then refused it.
func TestConfigWrite_RejectedWriteChangesNothing(t *testing.T) {
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer tlsServer.Close()
	verifies := func(b *azureBackend) bool {
		req, _ := http.NewRequest(http.MethodGet, tlsServer.URL, nil)
		resp, err := b.Transport().RoundTrip(req)
		if err == nil {
			resp.Body.Close()
		}
		// A self-signed server fails verification, and nothing else is wrong.
		var verifyErr *tls.CertificateVerificationError
		return errors.As(err, &verifyErr)
	}

	storage := newInmemStorage()
	b := configuredBackend(storage)
	require.True(t, verifies(b))

	resp := writeConfig(b, map[string]interface{}{
		"timeout":         99,
		"max_body_size":   int64(1024),
		"tls_skip_verify": true,
		"auto_auth_path":  "",
	})
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assertUnchanged(t, b)
	assert.True(t, verifies(b), "a rejected write must not have turned TLS verification off")
	assert.Empty(t, storage.data)

	resp = writeConfig(b, map[string]interface{}{"tls_skip_verify": true, "auto_auth_path": "auth/jwt/"})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.False(t, verifies(b))
}

// A bad ca_data is refused every time it is sent, not recorded as current by
// the first refusal and saved by the second.
func TestConfigWrite_BadCADataRefusedEveryTime(t *testing.T) {
	storage := newInmemStorage()
	b := configuredBackend(storage)
	for i := 0; i < 2; i++ {
		resp := writeConfig(b, map[string]interface{}{"ca_data": "not-a-certificate", "auto_auth_path": "auth/jwt/"})
		require.Equal(t, http.StatusBadRequest, resp.StatusCode, "attempt %d", i+1)
	}
	assertUnchanged(t, b)
	assert.Empty(t, storage.data)
}

// failingStorage refuses every write.
type failingStorage struct{ *inmemStorage }

func (failingStorage) Put(context.Context, *sdklogical.StorageEntry) error {
	return errors.New("storage unavailable")
}

// A write that cannot be persisted is not applied either.
func TestConfigWrite_UnpersistedWriteNotApplied(t *testing.T) {
	b := configuredBackend(failingStorage{newInmemStorage()})
	resp := writeConfig(b, map[string]interface{}{"timeout": 99, "auto_auth_path": "auth/other/"})
	require.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	assertUnchanged(t, b)
}
