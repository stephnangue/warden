package rds

import (
	"context"
	"sync"
	"testing"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/logger"
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

func setupBackend(t *testing.T) *rdsBackend {
	t.Helper()
	storage := newInmemStorage()
	ctx := context.Background()
	conf := &logical.BackendConfig{
		StorageView: storage,
		Logger:      testLogger(),
	}
	b, err := Factory(ctx, conf)
	require.NoError(t, err)
	return b.(*rdsBackend)
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
	assert.Equal(t, "rds", b.Type())
	assert.Equal(t, logical.ClassProvider, b.Class())
}

// --- Config tests ---

func TestConfigCRUD(t *testing.T) {
	b := setupBackend(t)
	ctx := context.Background()

	t.Run("default config", func(t *testing.T) {
		cfg := b.GetAccessConfig()
		assert.False(t, cfg.TransparentMode)
		assert.Equal(t, "", cfg.AutoAuthPath)
	})

	t.Run("set and get config", func(t *testing.T) {
		err := b.SetAccessConfig(ctx, &framework.AccessConfig{
			TransparentMode: true,
			AutoAuthPath:    "auth/jwt/",
		})
		require.NoError(t, err)

		cfg := b.GetAccessConfig()
		assert.True(t, cfg.TransparentMode)
		assert.Equal(t, "auth/jwt/", cfg.AutoAuthPath)
	})

	t.Run("config persists via HandleRequest", func(t *testing.T) {
		// Write config via HandleRequest
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config",
			Data: map[string]any{
				"transparent_mode": true,
				"auto_auth_path":   "auth/cert/",
			},
		})
		require.NoError(t, err)
		assert.Equal(t, 204, resp.StatusCode)

		// Read config via HandleRequest
		resp, err = b.HandleRequest(ctx, &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "config",
		})
		require.NoError(t, err)
		assert.Equal(t, true, resp.Data["transparent_mode"])
		assert.Equal(t, "auth/cert/", resp.Data["auto_auth_path"])
	})

	t.Run("transparent_mode without auto_auth_path fails", func(t *testing.T) {
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config",
			Data: map[string]any{
				"transparent_mode": true,
				"auto_auth_path":   "",
			},
		})
		require.NoError(t, err)
		assert.True(t, resp.IsError())
	})
}

// --- TransparentModeProvider tests ---

func TestTransparentModeProvider(t *testing.T) {
	b := setupBackend(t)
	ctx := context.Background()

	t.Run("disabled by default", func(t *testing.T) {
		assert.False(t, b.IsTransparentMode())
		assert.Equal(t, "", b.GetAutoAuthPath())
		assert.Equal(t, "", b.GetAuthRole("access/readonly"))
	})

	t.Run("enabled after config", func(t *testing.T) {
		err := b.SetAccessConfig(ctx, &framework.AccessConfig{
			TransparentMode: true,
			AutoAuthPath:    "auth/jwt/",
		})
		require.NoError(t, err)

		assert.True(t, b.IsTransparentMode())
		assert.Equal(t, "auth/jwt/", b.GetAutoAuthPath())
		assert.Equal(t, "", b.GetAuthRole("access/readonly"))
	})

	t.Run("IsUnauthenticatedPath always false", func(t *testing.T) {
		assert.False(t, b.IsUnauthenticatedPath("access/readonly"))
		assert.False(t, b.IsUnauthenticatedPath("config"))
	})
}

func TestIsTransparentPath(t *testing.T) {
	b := setupBackend(t)

	assert.True(t, b.IsTransparentPath("access/readonly"))
	assert.True(t, b.IsTransparentPath("access/readwrite"))
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
			"credential_spec": "rds-readonly",
			"db_name":         "myapp",
			"db_engine":       "postgres",
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
		assert.Equal(t, "rds-readonly", resp.Data["credential_spec"])
		assert.Equal(t, "myapp", resp.Data["db_name"])
		assert.Equal(t, "postgres", resp.Data["db_engine"])
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

	t.Run("delete grant", func(t *testing.T) {
		d := makeFieldData(grantsPath, map[string]interface{}{"name": "readonly"})
		resp, err := b.handleGrantDelete(ctx, req, d)
		require.NoError(t, err)
		assert.Equal(t, 204, resp.StatusCode)

		resp, err = b.handleGrantRead(ctx, req, d)
		require.NoError(t, err)
		assert.True(t, resp.IsError())
	})
}

// --- Access endpoint tests ---

func TestHandleGetAccess(t *testing.T) {
	b := setupBackend(t)
	ctx := context.Background()
	grantsPath := b.pathGrants()
	accessPath := b.pathAccess()

	// Create a grant first
	d := makeFieldData(grantsPath, map[string]interface{}{
		"name":            "readonly",
		"credential_spec": "rds-readonly",
		"db_name":         "myapp",
		"db_engine":       "postgres",
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
		assert.Equal(t, "rds-readonly", resp.AccessData.CredentialSpec)
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
				"auth_token": "iam-token-xyz",
				"db_host":    "mydb.rds.amazonaws.com",
				"db_port":    "5432",
				"db_user":    "app_readonly",
				"db_engine":  "postgres",
			},
		}

		result := resp.AccessData.ResponseBuilder(cred)
		connStr := result["connection_string"].(string)
		assert.Contains(t, connStr, "host=mydb.rds.amazonaws.com")
		assert.Contains(t, connStr, "port=5432")
		assert.Contains(t, connStr, "dbname=myapp")
		assert.Contains(t, connStr, "user=app_readonly")
		assert.Contains(t, connStr, "password=iam-token-xyz")
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
				"auth_token": "token",
				"db_host":    "h",
				"db_port":    "5432",
				"db_user":    "u",
				"db_engine":  "postgres",
			},
		}
		result := resp.AccessData.ResponseBuilder(cred)
		connStr := result["connection_string"].(string)
		assert.Contains(t, connStr, "application_name=")
	})
}

// --- formatConnectionString tests ---

func TestFormatConnectionString(t *testing.T) {
	cred := &credential.Credential{
		Data: map[string]string{
			"auth_token": "my-token",
			"db_host":    "mydb.rds.amazonaws.com",
			"db_port":    "5432",
			"db_user":    "app_user",
			"db_engine":  "postgres",
		},
	}

	t.Run("postgres", func(t *testing.T) {
		grant := &rdsGrant{DBName: "myapp", DBEngine: "postgres"}
		result := formatConnectionString(cred, grant, "workload-a")
		assert.Equal(t,
			"host=mydb.rds.amazonaws.com port=5432 dbname=myapp user=app_user password=my-token sslmode=require application_name=workload-a",
			result,
		)
	})

	t.Run("mysql", func(t *testing.T) {
		grant := &rdsGrant{DBName: "myapp", DBEngine: "mysql"}
		result := formatConnectionString(cred, grant, "workload-b")
		assert.Equal(t,
			"app_user:my-token@tcp(mydb.rds.amazonaws.com:5432)/myapp?tls=true&connectionAttributes=program_name:workload-b",
			result,
		)
	})

	t.Run("sqlserver", func(t *testing.T) {
		grant := &rdsGrant{DBName: "myapp", DBEngine: "sqlserver"}
		result := formatConnectionString(cred, grant, "workload-c")
		assert.Equal(t,
			"sqlserver://app_user:my-token@mydb.rds.amazonaws.com:5432?database=myapp&encrypt=true&app+name=workload-c",
			result,
		)
	})

	t.Run("engine fallback from credential", func(t *testing.T) {
		grant := &rdsGrant{DBName: "myapp", DBEngine: ""}
		result := formatConnectionString(cred, grant, "workload-d")
		assert.Contains(t, result, "host=")
		assert.Contains(t, result, "sslmode=require")
	})

	t.Run("token with special characters is escaped in mysql", func(t *testing.T) {
		specialCred := &credential.Credential{
			Data: map[string]string{
				"auth_token": "token/with+special=chars&more",
				"db_host":    "h",
				"db_port":    "3306",
				"db_user":    "u",
				"db_engine":  "mysql",
			},
		}
		grant := &rdsGrant{DBName: "db", DBEngine: "mysql"}
		result := formatConnectionString(specialCred, grant, "w")
		assert.NotContains(t, result, "token/with+special")
		assert.Contains(t, result, "token%2Fwith%2Bspecial%3Dchars%26more")
	})
}
