package framework

import (
	"context"
	"sync"
	"testing"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

func setupAccessBackend(t *testing.T) *AccessBackend {
	t.Helper()
	storage := newInmemStorage()
	b := &AccessBackend{
		Backend: &Backend{
			BackendType:  "test-access",
			BackendClass: logical.ClassProvider,
			Paths:        []*Path{},
		},
	}
	err := b.Setup(context.Background(), &logical.BackendConfig{
		StorageView: storage,
		Logger:      newTestLogger(),
	})
	require.NoError(t, err)
	return b
}

func TestAccessBackend_Setup(t *testing.T) {
	b := setupAccessBackend(t)
	assert.NotNil(t, b.StorageView)
	assert.NotNil(t, b.cfg)
}

func TestAccessBackend_TransparentMode(t *testing.T) {
	b := setupAccessBackend(t)

	t.Run("disabled by default", func(t *testing.T) {
		assert.False(t, b.IsTransparentMode())
		assert.Equal(t, "", b.GetAutoAuthPath())
	})

	t.Run("enabled after config", func(t *testing.T) {
		err := b.SetAccessConfig(context.Background(), &AccessConfig{AutoAuthPath: "auth/jwt/"})
		require.NoError(t, err)
		assert.True(t, b.IsTransparentMode())
		assert.Equal(t, "auth/jwt/", b.GetAutoAuthPath())
	})
}

func TestAccessBackend_GetAuthRole(t *testing.T) {
	b := setupAccessBackend(t)

	t.Run("from request data", func(t *testing.T) {
		req := &logical.Request{Data: map[string]any{"role": "admin"}}
		assert.Equal(t, "admin", b.GetAuthRole("path", req))
	})

	t.Run("nil request", func(t *testing.T) {
		assert.Equal(t, "", b.GetAuthRole("path", nil))
	})

	t.Run("no role in request", func(t *testing.T) {
		req := &logical.Request{Data: map[string]any{}}
		assert.Equal(t, "", b.GetAuthRole("path", req))
	})
}

func TestAccessBackend_IsTransparentPath(t *testing.T) {
	b := setupAccessBackend(t)

	assert.True(t, b.IsTransparentPath("access/readonly"))
	assert.True(t, b.IsTransparentPath("access/readwrite"))
	assert.False(t, b.IsTransparentPath("config"))
	assert.False(t, b.IsTransparentPath("grants/foo"))
}

func TestAccessBackend_IsTransparentPath_CustomPrefix(t *testing.T) {
	b := setupAccessBackend(t)
	b.AccessPathPrefix = "custom/"

	assert.True(t, b.IsTransparentPath("custom/foo"))
	assert.False(t, b.IsTransparentPath("access/foo"))
}

func TestAccessBackend_IsUnauthenticatedPath(t *testing.T) {
	b := setupAccessBackend(t)
	assert.False(t, b.IsUnauthenticatedPath("access/readonly"))
	assert.False(t, b.IsUnauthenticatedPath("config"))
}

func TestAccessBackend_ConfigPersistence(t *testing.T) {
	b := setupAccessBackend(t)
	ctx := context.Background()

	// Set config
	err := b.SetAccessConfig(ctx, &AccessConfig{AutoAuthPath: "auth/cert/"})
	require.NoError(t, err)

	// Verify it persisted by loading into a new backend with same storage
	b2 := &AccessBackend{
		Backend: &Backend{BackendType: "test", BackendClass: logical.ClassProvider},
	}
	err = b2.Setup(ctx, &logical.BackendConfig{
		StorageView: b.StorageView,
		Logger:      newTestLogger(),
	})
	require.NoError(t, err)
	assert.Equal(t, "auth/cert/", b2.GetAccessConfig().AutoAuthPath)
}

func TestAccessBackend_PathAccessConfig(t *testing.T) {
	b := setupAccessBackend(t)
	ctx := context.Background()
	path := b.PathAccessConfig()

	t.Run("read default config", func(t *testing.T) {
		d := &FieldData{Raw: map[string]interface{}{}, Schema: path.Fields}
		resp, err := b.handleConfigRead(ctx, nil, d)
		require.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)
		assert.Equal(t, "", resp.Data["auto_auth_path"])
	})

	t.Run("write config", func(t *testing.T) {
		d := &FieldData{
			Raw:    map[string]interface{}{"auto_auth_path": "auth/jwt/"},
			Schema: path.Fields,
		}
		resp, err := b.handleConfigWrite(ctx, nil, d)
		require.NoError(t, err)
		assert.Equal(t, 204, resp.StatusCode)
	})

	t.Run("read updated config", func(t *testing.T) {
		d := &FieldData{Raw: map[string]interface{}{}, Schema: path.Fields}
		resp, err := b.handleConfigRead(ctx, nil, d)
		require.NoError(t, err)
		assert.Equal(t, "auth/jwt/", resp.Data["auto_auth_path"])
	})
}

func TestAccessBackend_GetAccessConfig_NilCfg(t *testing.T) {
	b := &AccessBackend{Backend: &Backend{}}
	cfg := b.GetAccessConfig()
	assert.NotNil(t, cfg)
	assert.Equal(t, "", cfg.AutoAuthPath)
}

func TestAccessBackend_GetAutoAuthPath_NilCfg(t *testing.T) {
	b := &AccessBackend{Backend: &Backend{}}
	assert.Equal(t, "", b.GetAutoAuthPath())
}
