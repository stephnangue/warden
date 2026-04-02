package anthropic

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

func setupBackend(t *testing.T) *anthropicBackend {
	t.Helper()
	storage := newInmemStorage()
	ctx := context.Background()
	conf := &logical.BackendConfig{
		StorageView: storage,
		Logger:      testLogger(),
	}
	b, err := Factory(ctx, conf)
	require.NoError(t, err)
	return b.(*anthropicBackend)
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
	assert.Equal(t, "anthropic", b.Type())
	assert.Equal(t, logical.ClassProvider, b.Class())
	assert.Equal(t, DefaultAnthropicURL, b.anthropicURL)
	assert.Equal(t, DefaultAnthropicTimeout, b.Timeout)
	assert.Equal(t, framework.DefaultMaxBodySize, b.MaxBodySize)
}

func TestFactory_WithConfig(t *testing.T) {
	storage := newInmemStorage()
	ctx := context.Background()
	conf := &logical.BackendConfig{
		StorageView: storage,
		Logger:      testLogger(),
		Config: map[string]any{
			"anthropic_url":  "https://custom.anthropic.com",
			"timeout":        "60s",
			"auto_auth_path": "auth/jwt/",
			"default_role":   "reader",
		},
	}
	b, err := Factory(ctx, conf)
	require.NoError(t, err)
	ab := b.(*anthropicBackend)
	assert.Equal(t, "https://custom.anthropic.com", ab.anthropicURL)
	assert.Equal(t, 60.0, ab.Timeout.Seconds())
}

func TestFactory_InvalidConfig(t *testing.T) {
	storage := newInmemStorage()
	ctx := context.Background()
	conf := &logical.BackendConfig{
		StorageView: storage,
		Logger:      testLogger(),
		Config: map[string]any{
			"anthropic_url": "http://insecure.com",
		},
	}
	_, err := Factory(ctx, conf)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "https://")
}

// --- Initialize tests ---

func TestInitialize_NoStorage(t *testing.T) {
	b := &anthropicBackend{
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
		"anthropic_url": "https://saved.anthropic.com",
		"max_body_size": int64(5242880),
		"timeout":       "30s",
		"auto_auth_path": "auth/cert/",
		"default_role":   "admin",
	})
	_ = storage.Put(context.Background(), entry)

	b := setupBackend(t)
	b.StorageView = storage

	err := b.Initialize(context.Background())
	require.NoError(t, err)

	assert.Equal(t, "https://saved.anthropic.com", b.anthropicURL)
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
	assert.Equal(t, DefaultAnthropicURL, resp.Data["anthropic_url"])
	assert.Equal(t, framework.DefaultMaxBodySize, resp.Data["max_body_size"])
	assert.Equal(t, DefaultAnthropicTimeout.String(), resp.Data["timeout"])
	_ = path // used for setup
}

func TestConfigWrite(t *testing.T) {
	b := setupBackend(t)
	ctx := context.Background()
	path := b.pathConfig()

	t.Run("update config", func(t *testing.T) {
		d := makeFieldData(path, map[string]interface{}{
			"anthropic_url":  "https://custom.anthropic.com",
			"timeout":        120,
			"auto_auth_path": "auth/jwt/",
			"default_role":   "reader",
		})
		resp, err := b.handleConfigWrite(ctx, nil, d)
		require.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)
		assert.Equal(t, "https://custom.anthropic.com", b.anthropicURL)
	})

	t.Run("read back updated config", func(t *testing.T) {
		resp, err := b.handleConfigRead(ctx, nil, nil)
		require.NoError(t, err)
		assert.Equal(t, "https://custom.anthropic.com", resp.Data["anthropic_url"])
	})

	t.Run("invalid URL rejected", func(t *testing.T) {
		d := makeFieldData(path, map[string]interface{}{
			"anthropic_url":  "http://insecure.com",
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
			"anthropic_url": "https://api.anthropic.com",
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

// --- getAnthropicCredential tests ---

func TestGetAnthropicCredential(t *testing.T) {
	b := setupBackend(t)

	t.Run("nil credential", func(t *testing.T) {
		req := &logical.Request{}
		_, err := b.getAnthropicCredential(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no credential")
	})

	t.Run("wrong credential type", func(t *testing.T) {
		req := &logical.Request{
			Credential: &credential.Credential{
				Type: "aws_access_keys",
			},
		}
		_, err := b.getAnthropicCredential(req)
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
		_, err := b.getAnthropicCredential(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing api_key")
	})

	t.Run("valid credential", func(t *testing.T) {
		req := &logical.Request{
			Credential: &credential.Credential{
				Type: credential.TypeAPIKey,
				Data: map[string]string{"api_key": "sk-ant-test-key"},
			},
		}
		key, err := b.getAnthropicCredential(req)
		assert.NoError(t, err)
		assert.Equal(t, "sk-ant-test-key", key)
	})
}
