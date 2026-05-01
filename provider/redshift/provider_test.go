package redshift

import (
	"context"
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

func setupBackend(t *testing.T) *redshiftBackend {
	t.Helper()
	storage := newInmemStorage()
	ctx := context.Background()
	conf := &logical.BackendConfig{
		StorageView: storage,
		Logger:      testLogger(),
	}
	b, err := Factory(ctx, conf)
	require.NoError(t, err)
	return b.(*redshiftBackend)
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
	assert.Equal(t, "redshift", b.Type())
	assert.Equal(t, logical.ClassProvider, b.Class())
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
		err := b.SetAccessConfig(ctx, &framework.AccessConfig{
			AutoAuthPath: "auth/jwt/",
		})
		require.NoError(t, err)

		cfg := b.GetAccessConfig()
		assert.Equal(t, "auth/jwt/", cfg.AutoAuthPath)
	})

	t.Run("config persists via HandleRequest", func(t *testing.T) {
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config",
			Data: map[string]any{
				"auto_auth_path": "auth/cert/",
			},
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
		err := b.SetAccessConfig(ctx, &framework.AccessConfig{
			AutoAuthPath: "auth/jwt/",
		})
		require.NoError(t, err)

		assert.True(t, b.IsTransparentMode())
		assert.Equal(t, "auth/jwt/", b.GetAutoAuthPath())
	})

	t.Run("extracts role from query parameter", func(t *testing.T) {
		req := &logical.Request{
			Data: map[string]any{"role": "data-team"},
		}
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
	assert.True(t, b.IsTransparentPath("access/serverless"))
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
			"credential_spec": "redshift-readonly",
			"db_name":         "analytics",
			"description":     "Read-only access to analytics db",
		})
		resp, err := b.handleGrantWrite(ctx, req, d)
		require.NoError(t, err)
		assert.Equal(t, 204, resp.StatusCode)
	})

	t.Run("read grant", func(t *testing.T) {
		d := makeFieldData(grantsPath, map[string]interface{}{"name": "readonly"})
		resp, err := b.handleGrantRead(ctx, req, d)
		require.NoError(t, err)
		assert.Equal(t, "redshift-readonly", resp.Data["credential_spec"])
		assert.Equal(t, "analytics", resp.Data["db_name"])
		assert.Equal(t, "Read-only access to analytics db", resp.Data["description"])
	})

	t.Run("write grant without credential_spec fails", func(t *testing.T) {
		d := makeFieldData(grantsPath, map[string]interface{}{
			"name":    "bad-grant",
			"db_name": "analytics",
		})
		resp, err := b.handleGrantWrite(ctx, req, d)
		require.NoError(t, err)
		assert.True(t, resp.IsError())
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

	t.Run("update existing grant overwrites fields", func(t *testing.T) {
		d := makeFieldData(grantsPath, map[string]interface{}{
			"name":            "rw",
			"credential_spec": "spec-v1",
			"db_name":         "db1",
		})
		_, err := b.handleGrantWrite(ctx, req, d)
		require.NoError(t, err)

		d = makeFieldData(grantsPath, map[string]interface{}{
			"name":            "rw",
			"credential_spec": "spec-v2",
			"db_name":         "db2",
		})
		_, err = b.handleGrantWrite(ctx, req, d)
		require.NoError(t, err)

		d = makeFieldData(grantsPath, map[string]interface{}{"name": "rw"})
		resp, err := b.handleGrantRead(ctx, req, d)
		require.NoError(t, err)
		assert.Equal(t, "spec-v2", resp.Data["credential_spec"])
		assert.Equal(t, "db2", resp.Data["db_name"])
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
		"credential_spec": "redshift-readonly",
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

	t.Run("returns AccessData with correct spec", func(t *testing.T) {
		req := &logical.Request{}
		te := &logical.TokenEntry{PrincipalID: "workload-a"}
		req.SetTokenEntry(te)

		d := makeFieldData(accessPath, map[string]interface{}{"name": "readonly"})
		resp, err := b.handleGetAccess(ctx, req, d)
		require.NoError(t, err)
		require.NotNil(t, resp.AccessData)
		assert.Equal(t, "redshift-readonly", resp.AccessData.CredentialSpec)
	})

	t.Run("ResponseBuilder produces correct connection string", func(t *testing.T) {
		req := &logical.Request{}
		te := &logical.TokenEntry{PrincipalID: "workload-a"}
		req.SetTokenEntry(te)

		d := makeFieldData(accessPath, map[string]interface{}{"name": "readonly"})
		resp, err := b.handleGetAccess(ctx, req, d)
		require.NoError(t, err)
		require.NotNil(t, resp.AccessData)

		cred := &credential.Credential{
			LeaseTTL: 15 * time.Minute,
			Data: map[string]string{
				"auth_token": "redshift-temp-password",
				"db_host":    "my-cluster.abc123.us-east-1.redshift.amazonaws.com",
				"db_port":    "5439",
				"db_user":    "IAMR:warden-redshift-connect",
				"deployment": "provisioned",
			},
		}

		result := resp.AccessData.ResponseBuilder(cred)
		connStr := result["connection_string"].(string)
		assert.Contains(t, connStr, "host=my-cluster.abc123.us-east-1.redshift.amazonaws.com")
		assert.Contains(t, connStr, "port=5439")
		assert.Contains(t, connStr, "dbname=analytics")
		assert.Contains(t, connStr, "user=IAMR:warden-redshift-connect")
		assert.Contains(t, connStr, "password='redshift-temp-password'")
		assert.Contains(t, connStr, "sslmode=require")
		assert.Contains(t, connStr, "application_name=workload-a")
		assert.Equal(t, 900, result["lease_duration"])
	})

	t.Run("no token entry still works with empty principal", func(t *testing.T) {
		req := &logical.Request{}
		d := makeFieldData(accessPath, map[string]interface{}{"name": "readonly"})
		resp, err := b.handleGetAccess(ctx, req, d)
		require.NoError(t, err)
		require.NotNil(t, resp.AccessData)

		cred := &credential.Credential{
			LeaseTTL: 15 * time.Minute,
			Data: map[string]string{
				"auth_token": "tok",
				"db_host":    "h",
				"db_port":    "5439",
				"db_user":    "u",
			},
		}
		result := resp.AccessData.ResponseBuilder(cred)
		connStr := result["connection_string"].(string)
		assert.Contains(t, connStr, "application_name=")
	})

	t.Run("lease_duration reflects credential LeaseTTL", func(t *testing.T) {
		req := &logical.Request{}
		d := makeFieldData(accessPath, map[string]interface{}{"name": "readonly"})
		resp, err := b.handleGetAccess(ctx, req, d)
		require.NoError(t, err)

		cred := &credential.Credential{
			LeaseTTL: 60 * time.Minute,
			Data: map[string]string{
				"auth_token": "t",
				"db_host":    "h",
				"db_port":    "5439",
				"db_user":    "u",
			},
		}
		result := resp.AccessData.ResponseBuilder(cred)
		assert.Equal(t, 3600, result["lease_duration"])
	})

	t.Run("role query parameter is independent of grant selection", func(t *testing.T) {
		// Documented behavior: ?role= overrides the auth role used by the
		// transparent-mode provider, but the grant is always picked from
		// the path. So passing role=data-team to access/readonly must still
		// resolve the readonly grant.
		req := &logical.Request{Data: map[string]any{"role": "data-team"}}
		d := makeFieldData(accessPath, map[string]interface{}{"name": "readonly"})

		resp, err := b.handleGetAccess(ctx, req, d)
		require.NoError(t, err)
		require.NotNil(t, resp.AccessData)
		assert.Equal(t, "redshift-readonly", resp.AccessData.CredentialSpec)

		assert.Equal(t, "data-team", b.GetAuthRole("access/readonly", req))
	})
}

// --- formatConnectionString tests ---

func TestFormatConnectionString(t *testing.T) {
	t.Run("provisioned cluster", func(t *testing.T) {
		cred := &credential.Credential{
			Data: map[string]string{
				"auth_token": "secret-token",
				"db_host":    "my-cluster.abc123.us-east-1.redshift.amazonaws.com",
				"db_port":    "5439",
				"db_user":    "IAMR:warden-role",
			},
		}
		grant := &redshiftGrant{DBName: "analytics"}
		result := formatConnectionString(cred, grant, "workload-a")
		assert.Equal(t,
			"host=my-cluster.abc123.us-east-1.redshift.amazonaws.com port=5439 dbname=analytics user=IAMR:warden-role password='secret-token' sslmode=require application_name=workload-a",
			result,
		)
	})

	t.Run("password is single-quoted to handle special characters", func(t *testing.T) {
		cred := &credential.Credential{
			Data: map[string]string{
				"auth_token": "abc/def+ghi=jkl",
				"db_host":    "h",
				"db_port":    "5439",
				"db_user":    "u",
			},
		}
		grant := &redshiftGrant{DBName: "db"}
		result := formatConnectionString(cred, grant, "w")
		assert.Contains(t, result, "password='abc/def+ghi=jkl'")
	})

	t.Run("empty principal still produces application_name field", func(t *testing.T) {
		cred := &credential.Credential{
			Data: map[string]string{
				"auth_token": "t",
				"db_host":    "h",
				"db_port":    "5439",
				"db_user":    "u",
			},
		}
		grant := &redshiftGrant{DBName: "db"}
		result := formatConnectionString(cred, grant, "")
		assert.Contains(t, result, "application_name=")
	})

	t.Run("missing fields produce empty values, not panics", func(t *testing.T) {
		cred := &credential.Credential{Data: map[string]string{}}
		grant := &redshiftGrant{DBName: ""}
		assert.NotPanics(t, func() {
			_ = formatConnectionString(cred, grant, "")
		})
	})
}
