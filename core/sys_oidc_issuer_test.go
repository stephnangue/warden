package core

import (
	"context"
	"fmt"
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

	// Validation on a fresh config (no issuer_url stored yet): enabling without an
	// issuer_url fails, and a non-HTTPS URL fails. Neither is persisted, so the
	// real enable below still starts clean.
	assert.True(t, write(ctx, map[string]any{"enabled": true}).IsError())
	assert.True(t, write(ctx, map[string]any{"enabled": true, "issuer_url": "http://insecure"}).IsError())

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
	assert.Equal(t, int64(300), resp.Data["assertion_ttl"])

	// Partial update: changing one field must NOT reset the others. Enabling and
	// the issuer_url are carried forward from the stored config.
	resp = write(ctx, map[string]any{"key_rotation_period": "24h"})
	require.False(t, resp.IsError(), "partial update should succeed: %+v", resp.Data)
	resp = read(ctx)
	assert.Equal(t, true, resp.Data["enabled"], "enabled preserved")
	assert.Equal(t, "https://warden-oidc.example", resp.Data["issuer_url"], "issuer_url preserved")
	assert.Equal(t, int64(300), resp.Data["assertion_ttl"], "assertion_ttl preserved")
	assert.Equal(t, int64(24*3600), resp.Data["key_rotation_period"], "rotation period updated")

	// Enabling rotation surfaces a key_rotation status block, anchored on the key age, so
	// last_rotated_at/next_rotation are populated and running is true on this active node.
	kr, ok := resp.Data["key_rotation"].(map[string]any)
	require.True(t, ok, "key_rotation block present when rotation enabled")
	assert.Equal(t, true, kr["running"], "rotation loop running on the active node")
	assert.NotEmpty(t, kr["last_rotated_at"])
	assert.NotEmpty(t, kr["next_rotation"])
	assert.NotContains(t, kr, "last_error")

	// A recorded rotation failure surfaces in the block without advancing the anchor.
	prevRotatedAt := kr["last_rotated_at"]
	core.recordOIDCKeyRotationOutcome(ctx, fmt.Errorf("generate ES256 signing key: boom"))
	kr = read(ctx).Data["key_rotation"].(map[string]any)
	assert.Equal(t, "generate ES256 signing key: boom", kr["last_error"])
	assert.NotEmpty(t, kr["last_error_at"])
	assert.Equal(t, prevRotatedAt, kr["last_rotated_at"], "a failure must not advance the anchor")

	// key_rotation is gated on rotation being enabled: disabling it (period=0) hides the block.
	resp = write(ctx, map[string]any{"key_rotation_period": 0})
	require.False(t, resp.IsError())
	assert.NotContains(t, read(ctx).Data, "key_rotation", "block hidden when rotation disabled")

	// Disable: a partial write of just enabled=false tears the issuer down while
	// keeping the rest of the config for a later re-enable.
	resp = write(ctx, map[string]any{"enabled": false})
	require.False(t, resp.IsError())
	assert.Nil(t, core.OIDCIssuer())
	assert.Equal(t, "https://warden-oidc.example", read(ctx).Data["issuer_url"], "issuer_url retained while disabled")
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
	require.NoError(t, core.setupOIDCIssuer(ctx, false, false))
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

// TestMergePublisherConfig covers the publisher field-merge: cross-type fields
// are rejected, a type switch clears the previous type's fields, an omitted type
// is inherited, and masked/omitted secrets are preserved.
func TestMergePublisherConfig(t *testing.T) {
	// A field belonging to another type is rejected, not silently ignored.
	_, err := mergePublisherConfig(publisherConfig{}, map[string]any{
		"type": "s3", "bucket": "b", "region": "r", "dir": "/x",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only valid for type")

	_, err = mergePublisherConfig(publisherConfig{}, map[string]any{
		"type": "local_file", "dir": "/x", "base_url": "https://y",
	})
	require.Error(t, err)

	// A clean s3 config passes and carries no foreign fields.
	pc, err := mergePublisherConfig(publisherConfig{}, map[string]any{
		"type": "s3", "bucket": "b", "region": "r",
	})
	require.NoError(t, err)
	assert.Equal(t, "s3", pc.Type)
	assert.Equal(t, "b", pc.Bucket)
	assert.Empty(t, pc.BaseURL)

	// A type switch drops the previous type's fields (and its secret).
	prior := publisherConfig{Type: "http_put", BaseURL: "https://old", Autheader: "X", AuthValue: "sekret"}
	pc, err = mergePublisherConfig(prior, map[string]any{"type": "s3", "bucket": "b", "region": "r"})
	require.NoError(t, err)
	assert.Equal(t, "s3", pc.Type)
	assert.Empty(t, pc.BaseURL, "old http_put base_url must be cleared on a type switch")
	assert.Empty(t, pc.AuthValue, "old secret must be cleared on a type switch")
	assert.Equal(t, "b", pc.Bucket)

	// A partial edit that omits the type inherits it and preserves the rest.
	prior = publisherConfig{Type: "s3", Bucket: "b", Region: "r", AccessKeyID: "a", SecretAccessKey: "s"}
	pc, err = mergePublisherConfig(prior, map[string]any{"prefix": "p"})
	require.NoError(t, err)
	assert.Equal(t, "s3", pc.Type, "type inherited when omitted")
	assert.Equal(t, "p", pc.Prefix)
	assert.Equal(t, "b", pc.Bucket, "other fields preserved")
	assert.Equal(t, "s", pc.SecretAccessKey, "secret preserved")

	// A foreign field on an inherited-type partial edit is still rejected.
	_, err = mergePublisherConfig(prior, map[string]any{"base_url": "https://y"})
	require.Error(t, err)

	// A masked secret keeps the prior one (an update need not re-send it).
	prior = publisherConfig{Type: "http_put", BaseURL: "https://y", AuthValue: "sekret"}
	pc, err = mergePublisherConfig(prior, map[string]any{"type": "http_put", "auth_value": maskValue})
	require.NoError(t, err)
	assert.Equal(t, "sekret", pc.AuthValue)

	// A clean azure_blob (service-principal) config passes; prefix is shared with s3.
	pc, err = mergePublisherConfig(publisherConfig{}, map[string]any{
		"type": "azure_blob", "account_name": "wardenoidc", "container": "jwks", "prefix": "prod",
		"tenant_id": "t", "client_id": "ci", "client_secret": "cs", "secret_id": "sid",
		"endpoint": "https://wardenoidc.blob.core.usgovcloudapi.net/",
	})
	require.NoError(t, err)
	assert.Equal(t, "azure_blob", pc.Type)
	assert.Equal(t, "wardenoidc", pc.AccountName)
	assert.Equal(t, "jwks", pc.Container)
	assert.Equal(t, "prod", pc.Prefix)
	assert.Equal(t, "t", pc.TenantID)
	assert.Equal(t, "ci", pc.ClientID)
	assert.Equal(t, "cs", pc.ClientSecret)
	assert.Equal(t, "sid", pc.SecretID)
	assert.Equal(t, "https://wardenoidc.blob.core.usgovcloudapi.net/", pc.Endpoint)

	// Read masks the client secret but renders the non-secret fields plainly.
	masked := maskedPublisher(pc)
	assert.Equal(t, "wardenoidc", masked["account_name"])
	assert.Equal(t, "jwks", masked["container"])
	assert.Equal(t, "prod", masked["prefix"])
	assert.Equal(t, "t", masked["tenant_id"])
	assert.Equal(t, "ci", masked["client_id"])
	assert.Equal(t, "sid", masked["secret_id"])
	assert.Equal(t, maskValue, masked["client_secret"])

	// An s3 field under azure_blob is rejected.
	_, err = mergePublisherConfig(publisherConfig{}, map[string]any{
		"type": "azure_blob", "account_name": "a", "container": "c", "bucket": "b",
	})
	require.Error(t, err)

	// A masked client_secret keeps the prior one.
	prior = publisherConfig{Type: "azure_blob", AccountName: "a", Container: "c", ClientSecret: "realsecret"}
	pc, err = mergePublisherConfig(prior, map[string]any{"type": "azure_blob", "client_secret": maskValue})
	require.NoError(t, err)
	assert.Equal(t, "realsecret", pc.ClientSecret)

	// A clean gcs config passes; bucket/prefix/endpoint are shared and accepted here.
	pc, err = mergePublisherConfig(publisherConfig{}, map[string]any{
		"type": "gcs", "bucket": "my-jwks", "prefix": "prod",
		"credentials_json": `{"type":"service_account"}`, "endpoint": "https://storage.example",
	})
	require.NoError(t, err)
	assert.Equal(t, "gcs", pc.Type)
	assert.Equal(t, "my-jwks", pc.Bucket)
	assert.Equal(t, "prod", pc.Prefix)
	assert.Equal(t, `{"type":"service_account"}`, pc.CredentialsJSON)
	assert.Equal(t, "https://storage.example", pc.Endpoint)

	// Read masks the credentials but renders the non-secret fields plainly.
	masked = maskedPublisher(pc)
	assert.Equal(t, "my-jwks", masked["bucket"])
	assert.Equal(t, "prod", masked["prefix"])
	assert.Equal(t, "https://storage.example", masked["endpoint"])
	assert.Equal(t, maskValue, masked["credentials_json"])

	// An azure_blob field under gcs is rejected.
	_, err = mergePublisherConfig(publisherConfig{}, map[string]any{
		"type": "gcs", "bucket": "b", "credentials_json": "c", "account_name": "a",
	})
	require.Error(t, err)

	// Masked credentials_json keeps the prior one.
	prior = publisherConfig{Type: "gcs", Bucket: "b", CredentialsJSON: "realkey"}
	pc, err = mergePublisherConfig(prior, map[string]any{"type": "gcs", "credentials_json": maskValue})
	require.NoError(t, err)
	assert.Equal(t, "realkey", pc.CredentialsJSON)
}

// TestSysOIDCIssuerConfig_PublisherCrossTypeRejected verifies a cross-type
// publisher field is rejected at write time and nothing is persisted.
func TestSysOIDCIssuerConfig_PublisherCrossTypeRejected(t *testing.T) {
	backend, ctx, core := setupTestSystemBackend(t)
	schema := backend.pathOIDCIssuer()[0].Fields

	raw := map[string]any{
		"enabled":    true,
		"issuer_url": "https://iss.example",
		"publisher":  map[string]any{"type": "s3", "bucket": "b", "region": "r", "dir": "/x"},
	}
	resp, err := backend.handleOIDCIssuerConfigWrite(ctx, createTestRequest(logical.UpdateOperation, "oidc-issuer/config", raw), createFieldData(schema, raw))
	require.NoError(t, err)
	require.True(t, resp.IsError())
	assert.Contains(t, resp.Err.Error(), "only valid for type")

	// Rejected before persistence: no config stored.
	storage := NewBarrierView(core.barrier, oidcIssuerStorePrefix)
	cfg, _ := loadIssuerConfig(ctx, storage)
	assert.Nil(t, cfg, "a rejected write must not persist")
}
