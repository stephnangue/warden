package mcp_aws

import (
	"context"
	"sync"
	"testing"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/sdk/httpproxy"
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

func setupBackend(t *testing.T) *mcpAWSBackend {
	t.Helper()
	conf := &logical.BackendConfig{
		StorageView: newInmemStorage(),
		Logger:      testLogger(),
	}
	b, err := Factory(context.Background(), conf)
	require.NoError(t, err)
	return b.(*mcpAWSBackend)
}

func makeFieldData(path *framework.Path, raw map[string]any) *framework.FieldData {
	return &framework.FieldData{Raw: raw, Schema: path.Fields}
}

// --- Factory tests ---

func TestFactory_Defaults(t *testing.T) {
	b := setupBackend(t)
	assert.Equal(t, "mcp_aws", b.Type())
	assert.Equal(t, logical.ClassProvider, b.Class())
	assert.Equal(t, DefaultMCPAWSTimeout, b.Timeout)
	assert.Equal(t, framework.DefaultMaxBodySize, b.MaxBodySize)
	// Default URL yields region via arm 2 of the structured match.
	assert.Equal(t, "us-east-1", b.region)
	require.NotNil(t, b.upstreamURL)
	assert.Equal(t, "aws-mcp.us-east-1.api.aws", b.upstreamURL.Host)
}

func TestFactory_WithConfig(t *testing.T) {
	conf := &logical.BackendConfig{
		StorageView: newInmemStorage(),
		Logger:      testLogger(),
		Config: map[string]any{
			"mcp_aws_url":    "https://aws-mcp.eu-frankfurt-1.api.aws/mcp",
			"timeout":        "60s",
			"auto_auth_path": "auth/jwt/",
			"default_role":   "reader",
		},
	}
	b, err := Factory(context.Background(), conf)
	require.NoError(t, err)
	mb := b.(*mcpAWSBackend)
	assert.Equal(t, "eu-frankfurt-1", mb.region)
	assert.Equal(t, 60.0, mb.Timeout.Seconds())
	assert.Equal(t, "auth/jwt/", mb.TransparentConfig.AutoAuthPath)
	assert.Equal(t, "reader", mb.TransparentConfig.DefaultAuthRole)
}

func TestFactory_RegionRequiredForUnresolvableHost(t *testing.T) {
	// Custom host that doesn't match any inference arm; no region provided.
	rawConf := map[string]any{
		"mcp_aws_url":    "https://aws-mcp.cn-north-1.amazonaws.com.cn/mcp",
		"auto_auth_path": "auth/jwt/",
	}
	// Guard the test against a future ValidateConfig change rejecting this
	// URL for unrelated reasons — we want to assert the region-inference
	// fallback, not URL validation.
	require.NoError(t,
		httpproxy.ValidateConfig(rawConf, "mcp_aws_url"),
		"this test depends on the URL passing httpproxy.ValidateConfig",
	)

	conf := &logical.BackendConfig{
		StorageView: newInmemStorage(),
		Logger:      testLogger(),
		Config:      rawConf,
	}
	_, err := Factory(context.Background(), conf)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "region is required")
}

func TestFactory_ExplicitRegionForUnresolvableHost(t *testing.T) {
	conf := &logical.BackendConfig{
		StorageView: newInmemStorage(),
		Logger:      testLogger(),
		Config: map[string]any{
			"mcp_aws_url":    "https://aws-mcp.cn-north-1.amazonaws.com.cn/mcp",
			"region":         "cn-north-1",
			"auto_auth_path": "auth/jwt/",
		},
	}
	b, err := Factory(context.Background(), conf)
	require.NoError(t, err)
	mb := b.(*mcpAWSBackend)
	assert.Equal(t, "cn-north-1", mb.region)
}

// --- Initialize tests ---

func TestInitialize_EmptyStorage_NoOp(t *testing.T) {
	b := setupBackend(t)
	// Region from Factory defaults should persist after Initialize.
	require.NoError(t, b.Initialize(context.Background()))
	assert.Equal(t, "us-east-1", b.region)
}

// TestInitialize_PersistedConfigReload guards the highest-risk wiring step:
// after a server restart, SetTransparentConfig must be called again with the
// persisted values or isTransparentRequest silently returns false and every
// request 403s.
func TestInitialize_PersistedConfigReload(t *testing.T) {
	storage := newInmemStorage()
	entry, _ := sdklogical.StorageEntryJSON("config", map[string]any{
		"mcp_aws_url":    "https://aws-mcp.eu-frankfurt-1.api.aws/mcp",
		"timeout":        "5m",
		"auto_auth_path": "auth/cert/",
		"default_role":   "admin",
	})
	require.NoError(t, storage.Put(context.Background(), entry))

	// Fresh backend (simulates a restart).
	b := setupBackend(t)
	b.StorageView = storage

	require.NoError(t, b.Initialize(context.Background()))

	assert.Equal(t, "eu-frankfurt-1", b.region, "region must be repopulated from URL after restart")
	assert.Equal(t, "auth/cert/", b.TransparentConfig.AutoAuthPath, "AutoAuthPath must come back via SetTransparentConfig")
	assert.Equal(t, "admin", b.TransparentConfig.DefaultAuthRole)
	// GetAutoAuthPath is what core's isTransparentRequest checks.
	assert.Equal(t, "auth/cert/", b.GetAutoAuthPath())
}

// --- Config CRUD ---

func TestConfigRead(t *testing.T) {
	b := setupBackend(t)
	resp, err := b.handleConfigRead(context.Background(), nil, nil)
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, "us-east-1", resp.Data["region"])
	assert.Equal(t, DefaultMCPAWSURL, resp.Data["mcp_aws_url"])
	assert.Equal(t, framework.DefaultMaxBodySize, resp.Data["max_body_size"])
}

func TestConfigWrite_AutoAuthPathRequired(t *testing.T) {
	b := setupBackend(t)
	path := b.pathConfig()
	fd := makeFieldData(path, map[string]any{
		"mcp_aws_url": "https://aws-mcp.us-east-1.api.aws/mcp",
		// auto_auth_path intentionally absent
	})
	resp, err := b.handleConfigWrite(context.Background(), nil, fd)
	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

func TestConfigWrite_StaleRegionUpdate(t *testing.T) {
	b := setupBackend(t)
	path := b.pathConfig()

	// First write: us-east-1.
	fd1 := makeFieldData(path, map[string]any{
		"mcp_aws_url":    "https://aws-mcp.us-east-1.api.aws/mcp",
		"auto_auth_path": "auth/jwt/",
	})
	resp, err := b.handleConfigWrite(context.Background(), nil, fd1)
	require.NoError(t, err)
	require.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, "us-east-1", b.region)

	// Second write: only change the URL to a different-region host. The
	// region must move with it, not stay at us-east-1.
	fd2 := makeFieldData(path, map[string]any{
		"mcp_aws_url": "https://aws-mcp.eu-frankfurt-1.api.aws/mcp",
	})
	resp, err = b.handleConfigWrite(context.Background(), nil, fd2)
	require.NoError(t, err)
	require.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, "eu-frankfurt-1", b.region, "region must follow the URL change")
}

func TestConfigWrite_ExplicitRegionWins(t *testing.T) {
	b := setupBackend(t)
	path := b.pathConfig()
	// URL host doesn't yield a region; explicit region required + used.
	fd := makeFieldData(path, map[string]any{
		"mcp_aws_url":    "https://my-mcp.example.com/mcp",
		"region":         "us-west-2",
		"auto_auth_path": "auth/jwt/",
	})
	resp, err := b.handleConfigWrite(context.Background(), nil, fd)
	require.NoError(t, err)
	require.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, "us-west-2", b.region)
}
