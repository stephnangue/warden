package mistral

import (
	"context"
	"sync"
	"testing"

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

func setupBackend(t *testing.T) *mistralBackend {
	t.Helper()
	storage := newInmemStorage()
	ctx := context.Background()
	conf := &logical.BackendConfig{
		StorageView: storage,
		Logger:      testLogger(),
	}
	b, err := Factory(ctx, conf)
	require.NoError(t, err)
	return b.(*mistralBackend)
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
	assert.Equal(t, "mistral", b.Type())
	assert.Equal(t, logical.ClassProvider, b.Class())
	assert.Equal(t, DefaultMistralURL, b.mistralURL)
	assert.Equal(t, DefaultMistralTimeout, b.Timeout)
	assert.Equal(t, framework.DefaultMaxBodySize, b.MaxBodySize)
}

func TestFactory_WithConfig(t *testing.T) {
	storage := newInmemStorage()
	ctx := context.Background()
	conf := &logical.BackendConfig{
		StorageView: storage,
		Logger:      testLogger(),
		Config: map[string]any{
			"mistral_url":    "https://custom.mistral.ai",
			"timeout":        "60s",
			"auto_auth_path": "auth/jwt/",
			"default_role":   "reader",
		},
	}
	b, err := Factory(ctx, conf)
	require.NoError(t, err)
	mb := b.(*mistralBackend)
	assert.Equal(t, "https://custom.mistral.ai", mb.mistralURL)
	assert.Equal(t, 60.0, mb.Timeout.Seconds())
}

func TestFactory_InvalidConfig(t *testing.T) {
	storage := newInmemStorage()
	ctx := context.Background()
	conf := &logical.BackendConfig{
		StorageView: storage,
		Logger:      testLogger(),
		Config: map[string]any{
			"mistral_url": "http://insecure.com",
		},
	}
	_, err := Factory(ctx, conf)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "https://")
}

// --- Initialize tests ---

func TestInitialize_NoStorage(t *testing.T) {
	b := &mistralBackend{
		StreamingBackend: &framework.StreamingBackend{},
	}
	err := b.Initialize(context.Background())
	assert.NoError(t, err)
}

func TestInitialize_EmptyStorage(t *testing.T) {
	b := setupBackend(t)
	// Clear storage to simulate fresh start
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
		"mistral_url":    "https://saved.mistral.ai",
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

	assert.Equal(t, "https://saved.mistral.ai", b.mistralURL)
	assert.Equal(t, int64(5242880), b.MaxBodySize)
	assert.Equal(t, 30.0, b.Timeout.Seconds())
}

// --- Config CRUD tests ---

func TestConfigRead(t *testing.T) {
	b := setupBackend(t)
	ctx := context.Background()
	path := b.pathConfig()

	resp, err := b.handleConfigRead(ctx, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, DefaultMistralURL, resp.Data["mistral_url"])
	assert.Equal(t, framework.DefaultMaxBodySize, resp.Data["max_body_size"])
	assert.Equal(t, DefaultMistralTimeout.String(), resp.Data["timeout"])
	_ = path // used for setup
}

func TestConfigWrite(t *testing.T) {
	b := setupBackend(t)
	ctx := context.Background()
	path := b.pathConfig()

	t.Run("update config", func(t *testing.T) {
		d := makeFieldData(path, map[string]interface{}{
			"mistral_url":    "https://custom.mistral.ai",
			"timeout":        120,
			"auto_auth_path": "auth/jwt/",
			"default_role":   "reader",
		})
		resp, err := b.handleConfigWrite(ctx, nil, d)
		require.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)
		assert.Equal(t, "https://custom.mistral.ai", b.mistralURL)
	})

	t.Run("read back updated config", func(t *testing.T) {
		resp, err := b.handleConfigRead(ctx, nil, nil)
		require.NoError(t, err)
		assert.Equal(t, "https://custom.mistral.ai", resp.Data["mistral_url"])
	})

	t.Run("invalid URL rejected", func(t *testing.T) {
		d := makeFieldData(path, map[string]interface{}{
			"mistral_url":    "http://insecure.com",
			"auto_auth_path": "auth/jwt/",
		})
		resp, err := b.handleConfigWrite(ctx, nil, d)
		require.NoError(t, err)
		assert.Equal(t, 400, resp.StatusCode)
	})

	t.Run("missing auto_auth_path rejected", func(t *testing.T) {
		// Reset transparent config to have no auto_auth_path
		b.StreamingBackend.SetTransparentConfig(&framework.TransparentConfig{})
		d := makeFieldData(path, map[string]interface{}{
			"mistral_url": "https://api.mistral.ai",
		})
		resp, err := b.handleConfigWrite(ctx, nil, d)
		require.NoError(t, err)
		assert.Equal(t, 400, resp.StatusCode)
	})
}

// --- SensitiveConfigFields tests ---

func TestSensitiveConfigFields(t *testing.T) {
	b := setupBackend(t)
	fields := b.SensitiveConfigFields()
	assert.Empty(t, fields)
}

// --- getMistralAPIKey tests ---

func TestGetMistralAPIKey(t *testing.T) {
	b := setupBackend(t)

	t.Run("nil credential", func(t *testing.T) {
		req := &logical.Request{}
		_, err := b.getMistralAPIKey(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no credential")
	})

	t.Run("wrong credential type", func(t *testing.T) {
		req := &logical.Request{
			Credential: &credential.Credential{
				Type: "aws_access_keys",
			},
		}
		_, err := b.getMistralAPIKey(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported credential type")
	})

	t.Run("missing api_key field", func(t *testing.T) {
		req := &logical.Request{
			Credential: &credential.Credential{
				Type: credential.TypeAPIKey,
				Data: map[string]string{},
			},
		}
		_, err := b.getMistralAPIKey(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing api_key")
	})

	t.Run("valid credential", func(t *testing.T) {
		req := &logical.Request{
			Credential: &credential.Credential{
				Type: credential.TypeAPIKey,
				Data: map[string]string{"api_key": "sk-mistral-test-key"},
			},
		}
		key, err := b.getMistralAPIKey(req)
		assert.NoError(t, err)
		assert.Equal(t, "sk-mistral-test-key", key)
	})
}
