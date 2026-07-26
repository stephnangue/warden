package core

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSysOIDCIssuerConfig(t *testing.T) {
	backend, ctx, core := setupTestSystemBackend(t)
	schema := backend.pathOIDCIssuer()[0].Fields

	write := func(ctx context.Context, raw map[string]any) *logical.Response {
		resp, err := backend.handleOIDCIssuerConfigWrite(ctx, createTestRequest(logical.UpdateOperation, "oidc-issuer/config", raw), createFieldData(schema, raw))
		require.NoError(t, err)
		require.NotNil(t, resp)
		return resp
	}
	read := func(ctx context.Context) *logical.Response {
		resp, err := backend.handleOIDCIssuerConfigRead(ctx, createTestRequest(logical.ReadOperation, "oidc-issuer/config", nil), createFieldData(schema, nil))
		require.NoError(t, err)
		require.NotNil(t, resp)
		return resp
	}

	// Disabled by default: read before any config.
	resp := read(ctx)
	assert.Equal(t, false, resp.Data["enabled"])
	assert.Nil(t, core.OIDCIssuer())

	// Enable it: the issuer becomes ready and mints.
	resp = write(ctx, map[string]any{
		"enabled":       true,
		"issuer_url":    "https://warden-oidc.example",
		"assertion_ttl": 300,
	})
	require.False(t, resp.IsError(), "enable should succeed: %+v", resp.Data)
	require.NotNil(t, core.OIDCIssuer())
	assert.True(t, core.OIDCIssuer().Ready())

	// Read back.
	resp = read(ctx)
	assert.Equal(t, true, resp.Data["enabled"])
	assert.Equal(t, "https://warden-oidc.example", resp.Data["issuer_url"])
	assert.Equal(t, true, resp.Data["ready"])

	// Validation: enabled without issuer_url.
	assert.True(t, write(ctx, map[string]any{"enabled": true}).IsError())
	// Validation: non-HTTPS issuer_url.
	assert.True(t, write(ctx, map[string]any{"enabled": true, "issuer_url": "http://insecure"}).IsError())

	// Disable: issuer torn down.
	resp = write(ctx, map[string]any{"enabled": false})
	require.False(t, resp.IsError())
	assert.Nil(t, core.OIDCIssuer())
}

func TestSysOIDCIssuerConfig_Publisher(t *testing.T) {
	backend, ctx, core := setupTestSystemBackend(t)
	schema := backend.pathOIDCIssuer()[0].Fields
	write := func(raw map[string]any) *logical.Response {
		resp, err := backend.handleOIDCIssuerConfigWrite(ctx, createTestRequest(logical.UpdateOperation, "oidc-issuer/config", raw), createFieldData(schema, raw))
		require.NoError(t, err)
		require.NotNil(t, resp)
		return resp
	}
	read := func() *logical.Response {
		resp, err := backend.handleOIDCIssuerConfigRead(ctx, createTestRequest(logical.ReadOperation, "oidc-issuer/config", nil), createFieldData(schema, nil))
		require.NoError(t, err)
		return resp
	}

	// local_file publisher: enabling publishes the documents to the directory.
	dir := t.TempDir()
	resp := write(map[string]any{
		"enabled":    true,
		"issuer_url": "https://iss.example",
		"publisher":  map[string]any{"type": "local_file", "dir": dir},
	})
	require.False(t, resp.IsError(), "enable+publish should succeed: %+v", resp.Data)
	_, err := os.Stat(filepath.Join(dir, ".well-known", "openid-configuration"))
	require.NoError(t, err, "discovery must be published")
	_, err = os.Stat(filepath.Join(dir, "oidc", "jwks"))
	require.NoError(t, err, "jwks must be published")

	// http_put publisher with a secret auth header, pointed at a test origin.
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp = write(map[string]any{
		"enabled":    true,
		"issuer_url": "https://iss.example",
		"publisher":  map[string]any{"type": "http_put", "base_url": srv.URL, "auth_value": "Bearer tok1"},
	})
	require.False(t, resp.IsError(), "http_put enable should succeed: %+v", resp.Data)
	assert.Equal(t, "Bearer tok1", gotAuth, "auth header must be sent on publish")

	// Read masks the secret.
	pub := read().Data["publisher"].(map[string]any)
	assert.Equal(t, maskValue, pub["auth_value"])

	// Update without re-sending auth_value preserves the stored secret.
	gotAuth = ""
	resp = write(map[string]any{
		"enabled":    true,
		"issuer_url": "https://iss.example",
		"publisher":  map[string]any{"type": "http_put", "base_url": srv.URL},
	})
	require.False(t, resp.IsError(), "%+v", resp.Data)
	assert.Equal(t, "Bearer tok1", gotAuth, "auth_value must be preserved across an update that omits it")

	// The secret is preserved in storage, not wiped.
	storage := NewBarrierView(core.barrier, oidcIssuerStorePrefix)
	cfg, _ := loadIssuerConfig(ctx, storage)
	require.NotNil(t, cfg)
	assert.Equal(t, "Bearer tok1", cfg.Publisher.AuthValue)
}

// TestSysOIDCIssuerConfig_InvalidPublisherNotPersisted verifies a publisher that
// fails to build is rejected at write time and never reaches storage (so it can
// never brick a later unseal).
func TestSysOIDCIssuerConfig_InvalidPublisherNotPersisted(t *testing.T) {
	backend, ctx, core := setupTestSystemBackend(t)
	schema := backend.pathOIDCIssuer()[0].Fields

	raw := map[string]any{
		"enabled":    true,
		"issuer_url": "https://iss.example",
		"publisher":  map[string]any{"type": "s3", "bucket": "b", "region": "r"}, // missing keys
	}
	resp, err := backend.handleOIDCIssuerConfigWrite(ctx, createTestRequest(logical.UpdateOperation, "oidc-issuer/config", raw), createFieldData(schema, raw))
	require.NoError(t, err)
	require.True(t, resp.IsError(), "invalid publisher must be rejected")
	assert.Contains(t, resp.Err.Error(), "invalid publisher")

	// Nothing persisted, issuer not enabled.
	cfg, _ := loadIssuerConfig(ctx, NewBarrierView(core.barrier, oidcIssuerStorePrefix))
	assert.Nil(t, cfg, "the invalid config must not be persisted")
	assert.Nil(t, core.OIDCIssuer())
}

// TestSysOIDCIssuerConfig_PublishFailureSurfaces verifies a publish failure at
// config time is returned to the operator (not silently swallowed).
func TestSysOIDCIssuerConfig_PublishFailureSurfaces(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)
	schema := backend.pathOIDCIssuer()[0].Fields

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusForbidden) // origin rejects the write
	}))
	defer srv.Close()

	raw := map[string]any{
		"enabled":    true,
		"issuer_url": "https://iss.example",
		"publisher":  map[string]any{"type": "http_put", "base_url": srv.URL, "auth_value": "Bearer x"},
	}
	resp, err := backend.handleOIDCIssuerConfigWrite(ctx, createTestRequest(logical.UpdateOperation, "oidc-issuer/config", raw), createFieldData(schema, raw))
	require.NoError(t, err)
	require.True(t, resp.IsError(), "a publish failure must surface at config time")
	assert.Contains(t, resp.Err.Error(), "publishing failed")
}

// TestSetupOIDCIssuer_BadPublisherDoesNotFailUnseal verifies that a persisted
// config whose publisher no longer builds degrades to endpoint-only instead of
// failing setup (which runs during unseal).
func TestSetupOIDCIssuer_BadPublisherDoesNotFailUnseal(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()
	ctx := context.Background()
	storage := NewBarrierView(core.barrier, oidcIssuerStorePrefix)

	// Persist a config with a structurally-invalid publisher directly (simulating
	// a config that became invalid, or an older/looser write path).
	require.NoError(t, saveIssuerConfig(ctx, storage, &issuerConfig{
		Enabled:   true,
		IssuerURL: "https://iss.example",
		Publisher: publisherConfig{Type: "s3", Bucket: "b", Region: "r"}, // missing keys
	}))

	// Setup (as unseal would) must NOT fail; the issuer comes up, publisher is nil.
	require.NoError(t, core.setupOIDCIssuer(ctx, false))
	require.NotNil(t, core.OIDCIssuer())
	assert.True(t, core.OIDCIssuer().Ready())
	assert.Nil(t, core.oidcPublisher, "an invalid publisher degrades to endpoint-only")
}

// TestSysOIDCIssuerConfig_RotationValidation verifies a rotation period that does
// not exceed the JWKS cache TTL is rejected.
func TestSysOIDCIssuerConfig_RotationValidation(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)
	schema := backend.pathOIDCIssuer()[0].Fields

	raw := map[string]any{
		"enabled":             true,
		"issuer_url":          "https://iss.example",
		"key_rotation_period": 30,
		"jwks_cache_ttl":      60, // period <= cache TTL
	}
	resp, err := backend.handleOIDCIssuerConfigWrite(ctx, createTestRequest(logical.UpdateOperation, "oidc-issuer/config", raw), createFieldData(schema, raw))
	require.NoError(t, err)
	require.True(t, resp.IsError())
	assert.Contains(t, resp.Err.Error(), "must exceed jwks_cache_ttl")
}

func TestSysOIDCIssuerConfig_RootNamespaceOnly(t *testing.T) {
	backend, _, _ := setupTestSystemBackend(t)
	schema := backend.pathOIDCIssuer()[0].Fields

	childCtx := namespace.ContextWithNamespace(context.Background(), &namespace.Namespace{ID: "child", Path: "/child/"})
	raw := map[string]any{"enabled": true, "issuer_url": "https://warden-oidc.example"}

	// A child namespace can neither write nor read the global issuer config.
	resp, err := backend.handleOIDCIssuerConfigWrite(childCtx, createTestRequest(logical.UpdateOperation, "oidc-issuer/config", raw), createFieldData(schema, raw))
	require.NoError(t, err)
	require.True(t, resp.IsError())
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)

	resp, err = backend.handleOIDCIssuerConfigRead(childCtx, createTestRequest(logical.ReadOperation, "oidc-issuer/config", nil), createFieldData(schema, nil))
	require.NoError(t, err)
	require.True(t, resp.IsError())
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}
