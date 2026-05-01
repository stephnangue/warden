package dbaccess

import (
	"context"
	"fmt"
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

// testSpec is a sample provider spec used to exercise the framework's shared
// behavior. It declares one provider-specific grant field (`db_name`) and a
// trivial formatter that echoes its inputs into a deterministic string.
var testSpec = &ProviderSpec{
	Name:     "testprov",
	HelpText: "test provider for dbaccess framework",
	GrantFields: map[string]*framework.FieldSchema{
		"db_name": {
			Type:        framework.TypeString,
			Description: "Database name",
		},
	},
	FormatAccess: func(cred *credential.Credential, grant Grant, principal string) map[string]interface{} {
		return map[string]interface{}{
			"connection_string": fmt.Sprintf("%s/%s/%s/%s", grant["db_name"], cred.Data["db_user"], cred.Data["auth_token"], principal),
			"lease_duration":    int(cred.LeaseTTL.Seconds()),
		}
	},
}

func setupBackend(t *testing.T) *dbBackend {
	t.Helper()
	storage := newInmemStorage()
	ctx := context.Background()
	conf := &logical.BackendConfig{
		StorageView: storage,
		Logger:      testLogger(),
	}
	b, err := NewFactory(testSpec)(ctx, conf)
	require.NoError(t, err)
	return b.(*dbBackend)
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
	assert.Equal(t, "testprov", b.Type())
	assert.Equal(t, logical.ClassProvider, b.Class())
}

func TestFactory_RequiresName(t *testing.T) {
	bad := &ProviderSpec{
		FormatAccess: testSpec.FormatAccess,
	}
	_, err := NewFactory(bad)(context.Background(), &logical.BackendConfig{
		StorageView: newInmemStorage(),
		Logger:      testLogger(),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Name")
}

func TestFactory_RequiresFormatAccess(t *testing.T) {
	bad := &ProviderSpec{
		Name: "bad",
	}
	_, err := NewFactory(bad)(context.Background(), &logical.BackendConfig{
		StorageView: newInmemStorage(),
		Logger:      testLogger(),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "FormatAccess")
}

// --- Config tests ---

func TestConfigCRUD(t *testing.T) {
	b := setupBackend(t)
	ctx := context.Background()

	t.Run("default config", func(t *testing.T) {
		cfg := b.GetAccessConfig()
		assert.Equal(t, "", cfg.AutoAuthPath)
	})

	t.Run("set and get config", func(t *testing.T) {
		err := b.SetAccessConfig(ctx, &framework.AccessConfig{AutoAuthPath: "auth/jwt/"})
		require.NoError(t, err)

		cfg := b.GetAccessConfig()
		assert.Equal(t, "auth/jwt/", cfg.AutoAuthPath)
	})

	t.Run("config persists via HandleRequest", func(t *testing.T) {
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config",
			Data:      map[string]any{"auto_auth_path": "auth/cert/"},
		})
		require.NoError(t, err)
		assert.Equal(t, 204, resp.StatusCode)

		resp, err = b.HandleRequest(ctx, &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "config",
		})
		require.NoError(t, err)
		assert.Equal(t, "auth/cert/", resp.Data["auto_auth_path"])
	})
}

// --- TransparentModeProvider tests ---

func TestTransparentModeProvider(t *testing.T) {
	b := setupBackend(t)
	ctx := context.Background()

	t.Run("disabled by default", func(t *testing.T) {
		assert.False(t, b.IsTransparentMode())
		assert.Equal(t, "", b.GetAutoAuthPath())
	})

	t.Run("enabled after config with auto_auth_path", func(t *testing.T) {
		err := b.SetAccessConfig(ctx, &framework.AccessConfig{AutoAuthPath: "auth/jwt/"})
		require.NoError(t, err)

		assert.True(t, b.IsTransparentMode())
		assert.Equal(t, "auth/jwt/", b.GetAutoAuthPath())
	})

	t.Run("extracts role from query parameter", func(t *testing.T) {
		req := &logical.Request{Data: map[string]any{"role": "data-team"}}
		assert.Equal(t, "data-team", b.GetAuthRole("access/readonly", req))
	})

	t.Run("returns empty when no role in request", func(t *testing.T) {
		req := &logical.Request{Data: map[string]any{}}
		assert.Equal(t, "", b.GetAuthRole("access/readonly", req))
	})

	t.Run("IsUnauthenticatedPath always false", func(t *testing.T) {
		assert.False(t, b.IsUnauthenticatedPath("access/readonly"))
		assert.False(t, b.IsUnauthenticatedPath("config"))
	})
}

func TestIsTransparentPath(t *testing.T) {
	b := setupBackend(t)

	assert.True(t, b.IsTransparentPath("access/readonly"))
	assert.True(t, b.IsTransparentPath("access/anything"))
	assert.False(t, b.IsTransparentPath("grants/readonly"))
	assert.False(t, b.IsTransparentPath("config"))
	assert.False(t, b.IsTransparentPath(""))
}

// --- Grant CRUD tests ---

func TestGrantCRUD(t *testing.T) {
	b := setupBackend(t)
	ctx := context.Background()
	req := &logical.Request{}
	grantsPath := b.pathGrants()

	t.Run("read nonexistent grant returns error", func(t *testing.T) {
		d := makeFieldData(grantsPath, map[string]interface{}{"name": "nonexistent"})
		resp, err := b.handleGrantRead(ctx, req, d)
		require.NoError(t, err)
		assert.True(t, resp.IsError())
	})

	t.Run("write grant", func(t *testing.T) {
		d := makeFieldData(grantsPath, map[string]interface{}{
			"name":            "readonly",
			"credential_spec": "the-spec",
			"db_name":         "myapp",
			"description":     "Read-only access",
		})
		resp, err := b.handleGrantWrite(ctx, req, d)
		require.NoError(t, err)
		assert.Equal(t, 204, resp.StatusCode)
	})

	t.Run("read grant", func(t *testing.T) {
		d := makeFieldData(grantsPath, map[string]interface{}{"name": "readonly"})
		resp, err := b.handleGrantRead(ctx, req, d)
		require.NoError(t, err)
		assert.Equal(t, "the-spec", resp.Data["credential_spec"])
		assert.Equal(t, "myapp", resp.Data["db_name"])
		assert.Equal(t, "Read-only access", resp.Data["description"])
	})

	t.Run("write grant without credential_spec fails", func(t *testing.T) {
		d := makeFieldData(grantsPath, map[string]interface{}{
			"name":    "bad-grant",
			"db_name": "myapp",
		})
		resp, err := b.handleGrantWrite(ctx, req, d)
		require.NoError(t, err)
		assert.True(t, resp.IsError())
	})

	t.Run("update grant overwrites fields", func(t *testing.T) {
		d := makeFieldData(grantsPath, map[string]interface{}{
			"name":            "rw",
			"credential_spec": "v1",
			"db_name":         "db1",
		})
		_, err := b.handleGrantWrite(ctx, req, d)
		require.NoError(t, err)

		d = makeFieldData(grantsPath, map[string]interface{}{
			"name":            "rw",
			"credential_spec": "v2",
			"db_name":         "db2",
		})
		_, err = b.handleGrantWrite(ctx, req, d)
		require.NoError(t, err)

		d = makeFieldData(grantsPath, map[string]interface{}{"name": "rw"})
		resp, err := b.handleGrantRead(ctx, req, d)
		require.NoError(t, err)
		assert.Equal(t, "v2", resp.Data["credential_spec"])
		assert.Equal(t, "db2", resp.Data["db_name"])
	})

	t.Run("delete grant", func(t *testing.T) {
		d := makeFieldData(grantsPath, map[string]interface{}{"name": "readonly"})
		resp, err := b.handleGrantDelete(ctx, req, d)
		require.NoError(t, err)
		assert.Equal(t, 204, resp.StatusCode)

		resp, err = b.handleGrantRead(ctx, req, d)
		require.NoError(t, err)
		assert.True(t, resp.IsError())
	})

	t.Run("legacy JSON shape decodes as Grant map", func(t *testing.T) {
		// Storage compatibility: an entry written by the pre-refactor code
		// (typed struct serialized as JSON with the same field names) must
		// still decode through the framework's getGrant.
		legacyJSON := []byte(`{"credential_spec":"legacy-spec","db_name":"legacy-db","description":"old"}`)
		require.NoError(t, b.StorageView.Put(ctx, &sdklogical.StorageEntry{
			Key:   "grants/legacy",
			Value: legacyJSON,
		}))

		grant, err := b.getGrant(ctx, "legacy")
		require.NoError(t, err)
		require.NotNil(t, grant)
		assert.Equal(t, "legacy-spec", grant["credential_spec"])
		assert.Equal(t, "legacy-db", grant["db_name"])
		assert.Equal(t, "old", grant["description"])
	})
}

// --- Access endpoint tests ---

func TestHandleGetAccess(t *testing.T) {
	b := setupBackend(t)
	ctx := context.Background()
	grantsPath := b.pathGrants()
	accessPath := b.pathAccess()

	d := makeFieldData(grantsPath, map[string]interface{}{
		"name":            "readonly",
		"credential_spec": "my-spec",
		"db_name":         "analytics",
	})
	_, err := b.handleGrantWrite(ctx, &logical.Request{}, d)
	require.NoError(t, err)

	t.Run("nonexistent grant returns error", func(t *testing.T) {
		req := &logical.Request{}
		d := makeFieldData(accessPath, map[string]interface{}{"name": "nonexistent"})
		resp, err := b.handleGetAccess(ctx, req, d)
		require.NoError(t, err)
		assert.True(t, resp.IsError())
	})

	t.Run("AccessData carries grant's credential_spec", func(t *testing.T) {
		req := &logical.Request{}
		req.SetTokenEntry(&logical.TokenEntry{PrincipalID: "workload-a"})

		d := makeFieldData(accessPath, map[string]interface{}{"name": "readonly"})
		resp, err := b.handleGetAccess(ctx, req, d)
		require.NoError(t, err)
		require.NotNil(t, resp.AccessData)
		assert.Equal(t, "my-spec", resp.AccessData.CredentialSpec)
	})

	t.Run("ResponseBuilder calls FormatAccess with grant + cred + principal", func(t *testing.T) {
		req := &logical.Request{}
		req.SetTokenEntry(&logical.TokenEntry{PrincipalID: "workload-a"})

		d := makeFieldData(accessPath, map[string]interface{}{"name": "readonly"})
		resp, err := b.handleGetAccess(ctx, req, d)
		require.NoError(t, err)
		require.NotNil(t, resp.AccessData)

		cred := &credential.Credential{
			LeaseTTL: 15 * time.Minute,
			Data: map[string]string{
				"auth_token": "tok",
				"db_user":    "u",
			},
		}
		out := resp.AccessData.ResponseBuilder(cred)
		// testSpec.FormatAccess builds: db_name/user/token/principal
		assert.Equal(t, "analytics/u/tok/workload-a", out["connection_string"])
		assert.Equal(t, 900, out["lease_duration"])
	})

	t.Run("no token entry yields empty principal", func(t *testing.T) {
		req := &logical.Request{}
		d := makeFieldData(accessPath, map[string]interface{}{"name": "readonly"})
		resp, err := b.handleGetAccess(ctx, req, d)
		require.NoError(t, err)
		require.NotNil(t, resp.AccessData)

		cred := &credential.Credential{
			LeaseTTL: 15 * time.Minute,
			Data:     map[string]string{"auth_token": "t", "db_user": "u"},
		}
		out := resp.AccessData.ResponseBuilder(cred)
		assert.Equal(t, "analytics/u/t/", out["connection_string"])
	})

	t.Run("?role= is independent of grant selection", func(t *testing.T) {
		// Documented contract: role overrides the auth role; the grant is
		// always picked from the path.
		req := &logical.Request{Data: map[string]any{"role": "data-team"}}

		d := makeFieldData(accessPath, map[string]interface{}{"name": "readonly"})
		resp, err := b.handleGetAccess(ctx, req, d)
		require.NoError(t, err)
		require.NotNil(t, resp.AccessData)
		assert.Equal(t, "my-spec", resp.AccessData.CredentialSpec)

		assert.Equal(t, "data-team", b.GetAuthRole("access/readonly", req))
	})
}
