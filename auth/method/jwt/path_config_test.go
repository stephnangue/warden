// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package jwt

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// testLoggerConfig creates a logger for tests that discards output
func testLoggerConfig() *logger.GatedLogger {
	config := &logger.Config{
		Level:   logger.ErrorLevel,
		Format:  logger.JSONFormat,
		Outputs: []io.Writer{io.Discard},
	}
	gateConfig := logger.GatedWriterConfig{
		Underlying: io.Discard,
	}
	gl, _ := logger.NewGatedLogger(config, gateConfig)
	return gl
}

// =============================================================================
// pathConfig Structure Tests
// =============================================================================

func TestPathConfig_Pattern(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLoggerConfig(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*jwtAuthBackend)
	path := b.pathConfig()

	assert.Equal(t, "config", path.Pattern)
}

func TestPathConfig_Fields(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLoggerConfig(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*jwtAuthBackend)
	path := b.pathConfig()

	// Check required fields exist
	expectedFields := []string{
		"oidc_discovery_url",
		"oidc_discovery_ca_pem",
		"jwks_url",
		"jwks_ca_pem",
		"bound_issuer",
		"bound_audiences",
		"bound_subject",
		"user_claim",
		"token_ttl",
	}

	for _, field := range expectedFields {
		_, exists := path.Fields[field]
		assert.True(t, exists, "Field %s should exist", field)
	}
	for _, field := range []string{"default_role", "groups_claim", "group_policy_prefix"} {
		assert.NotContains(t, path.Fields, field, "removed field %s", field)
	}
}

func TestPathConfig_FieldTypes(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLoggerConfig(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*jwtAuthBackend)
	path := b.pathConfig()

	tests := []struct {
		field        string
		expectedType framework.FieldType
	}{
		{"oidc_discovery_url", framework.TypeString},
		{"oidc_discovery_ca_pem", framework.TypeString},
		{"jwks_url", framework.TypeString},
		{"jwks_ca_pem", framework.TypeString},
		{"bound_issuer", framework.TypeString},
		{"bound_audiences", framework.TypeCommaStringSlice},
		{"bound_subject", framework.TypeString},
		{"user_claim", framework.TypeString},
		{"token_ttl", framework.TypeDurationSecond},
	}

	for _, tc := range tests {
		t.Run(tc.field, func(t *testing.T) {
			field, exists := path.Fields[tc.field]
			require.True(t, exists, "Field %s should exist", tc.field)
			assert.Equal(t, tc.expectedType, field.Type, "Field %s should have correct type", tc.field)
		})
	}
}

func TestPathConfig_DefaultValues(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLoggerConfig(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*jwtAuthBackend)
	path := b.pathConfig()

	// Check defaults
	userClaimField := path.Fields["user_claim"]
	assert.Equal(t, "sub", userClaimField.Default)
}

func TestPathConfig_Operations(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLoggerConfig(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*jwtAuthBackend)
	path := b.pathConfig()

	// Check operations exist
	_, hasRead := path.Operations[logical.ReadOperation]
	_, hasUpdate := path.Operations[logical.UpdateOperation]

	assert.True(t, hasRead, "Should have read operation")
	assert.True(t, hasUpdate, "Should have update operation")
}

// =============================================================================
// handleConfigRead Tests
// =============================================================================

func TestHandleConfigRead_NoConfig(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLoggerConfig(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*jwtAuthBackend)
	// Ensure config is nil
	b.config = nil

	req := &logical.Request{}
	d := &framework.FieldData{
		Raw:    map[string]any{},
		Schema: b.pathConfig().Fields,
	}

	resp, err := b.handleConfigRead(ctx, req, d)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.NotNil(t, resp.Data)
	assert.Empty(t, resp.Data)
}

func TestHandleConfigRead_WithConfig(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLoggerConfig(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*jwtAuthBackend)
	b.config = &JWTAuthConfig{
		JWKSURL:        "https://example.com/.well-known/jwks.json",
		BoundIssuer:    "https://issuer.example.com",
		BoundAudiences: []string{"aud1", "aud2"},
		BoundSubject:   "expected-subject",
		UserClaim:      "email",
		TokenTTL:       2 * time.Hour,
	}

	req := &logical.Request{}
	d := &framework.FieldData{
		Raw:    map[string]any{},
		Schema: b.pathConfig().Fields,
	}

	resp, err := b.handleConfigRead(ctx, req, d)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "https://example.com/.well-known/jwks.json", resp.Data["jwks_url"])
	assert.Equal(t, "https://issuer.example.com", resp.Data["bound_issuer"])
	assert.Equal(t, []string{"aud1", "aud2"}, resp.Data["bound_audiences"])
	assert.Equal(t, "expected-subject", resp.Data["bound_subject"])
	assert.Equal(t, "email", resp.Data["user_claim"])
	assert.NotContains(t, resp.Data, "groups_claim")
	assert.Equal(t, "2h0m0s", resp.Data["token_ttl"])
}

func TestHandleConfigRead_OIDC(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLoggerConfig(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*jwtAuthBackend)
	b.config = &JWTAuthConfig{
		OIDCDiscoveryURL: "https://issuer.example.com/.well-known/openid-configuration",
		UserClaim:        "sub",
		TokenTTL:         1 * time.Hour,
	}

	req := &logical.Request{}
	d := &framework.FieldData{
		Raw:    map[string]any{},
		Schema: b.pathConfig().Fields,
	}

	resp, err := b.handleConfigRead(ctx, req, d)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "https://issuer.example.com/.well-known/openid-configuration", resp.Data["oidc_discovery_url"])
}

// =============================================================================
// handleConfigWrite Tests
// =============================================================================

func TestHandleConfigWrite_NoKeySource(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLoggerConfig(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*jwtAuthBackend)

	req := &logical.Request{}
	d := &framework.FieldData{
		Raw: map[string]any{
			"user_claim": "email",
		},
		Schema: b.pathConfig().Fields,
	}

	resp, err := b.handleConfigWrite(ctx, req, d)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.NotNil(t, resp.Err)
	assert.Contains(t, resp.Err.Error(), "exactly one of")
}

// =============================================================================
// Help Text Tests
// =============================================================================

func TestPathConfig_HelpText(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLoggerConfig(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*jwtAuthBackend)
	path := b.pathConfig()

	assert.NotEmpty(t, path.HelpSynopsis)
	assert.NotEmpty(t, path.HelpDescription)
}

// =============================================================================
// Field Description Tests
// =============================================================================

func TestPathConfig_FieldDescriptions(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLoggerConfig(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*jwtAuthBackend)
	path := b.pathConfig()

	// All fields should have descriptions
	for name, field := range path.Fields {
		assert.NotEmpty(t, field.Description, "Field %s should have a description", name)
	}
}

func TestHandleConfigWrite_PersistsToStorage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"keys":[]}`))
	}))
	defer srv.Close()

	b, ctx := createTestBackendWithStorage(t)

	d := &framework.FieldData{
		Raw: map[string]any{
			"jwks_url":        srv.URL,
			"bound_audiences": []string{"warden"},
		},
		Schema: b.pathConfig().Fields,
	}

	resp, err := b.handleConfigWrite(ctx, &logical.Request{}, d)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify config was persisted to storage
	entry, err := b.storageView.Get(ctx, "config")
	require.NoError(t, err)
	assert.NotNil(t, entry)
}

// =============================================================================
// Role Update with all fields
// =============================================================================

func TestHandleConfigWrite_MergesExisting(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"keys":[]}`))
	}))
	defer srv.Close()

	b, ctx := createTestBackendWithStorage(t)

	// First write
	d := &framework.FieldData{
		Raw: map[string]any{
			"jwks_url":        srv.URL,
			"bound_audiences": []string{"warden"},
		},
		Schema: b.pathConfig().Fields,
	}
	resp, err := b.handleConfigWrite(ctx, &logical.Request{}, d)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Second write - update bound_issuer only
	d2 := &framework.FieldData{
		Raw: map[string]any{
			"bound_issuer": "https://issuer.example.com",
		},
		Schema: b.pathConfig().Fields,
	}
	resp2, err := b.handleConfigWrite(ctx, &logical.Request{}, d2)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp2.StatusCode)
	assert.Equal(t, "https://issuer.example.com", b.config.BoundIssuer)
}

// =============================================================================
// Config keys of the role era
// =============================================================================

// A stored config that still sets default_role, groups_claim or
// group_policy_prefix loads without them, and a read warns about each; a
// write that sets one is refused and changes nothing; any other write stores
// the config without them.
func TestConfig_RemovedKeys(t *testing.T) {
	_, pemStr := genTestPubKeyPEM(t, "ECDSA")
	b, ctx := createTestBackendWithStorage(t)
	entry, err := sdklogical.StorageEntryJSON("config", map[string]any{
		"jwt_validation_pubkeys": []string{pemStr},
		"bound_audiences":        []string{"warden"},
		"default_role":           "reader",
		"groups_claim":           "groups",
		"group_policy_prefix":    "group-",
	})
	require.NoError(t, err)
	require.NoError(t, b.storageView.Put(ctx, entry))
	require.NoError(t, b.Initialize(ctx))

	read := func() *logical.Response {
		resp, err := b.handleConfigRead(ctx, &logical.Request{}, &framework.FieldData{})
		require.NoError(t, err)
		return resp
	}
	resp := read()
	warnings, _ := resp.Data["warnings"].([]string)
	require.Len(t, warnings, 3)
	for i, key := range []string{"default_role", "group_policy_prefix", "groups_claim"} {
		assert.Contains(t, warnings[i], key+" was removed and is ignored")
		assert.NotContains(t, resp.Data, key)
	}
	assert.Equal(t, []string{"warden"}, resp.Data["bound_audiences"], "the rest of the config loads")

	before := b.config
	for _, raw := range []map[string]any{
		{"default_role": "reader"},
		{"groups_claim": "groups", "user_claim": "email"},
		{"group_policy_prefix": "g-"},
	} {
		resp := writeConfig(b, raw)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode, "write %v", raw)
		assert.Contains(t, resp.Err.Error(), "was removed")
		assert.Same(t, before, b.config, "a refused write changes nothing")
	}
	assert.Equal(t, http.StatusOK, writeConfig(b, map[string]any{"default_role": ""}).StatusCode,
		"an empty value sets nothing")

	require.Equal(t, http.StatusOK, writeConfig(b, map[string]any{"user_claim": "email"}).StatusCode)
	assert.NotContains(t, read().Data, "warnings")
	stored, err := b.storageView.Get(ctx, "config")
	require.NoError(t, err)
	var storedMap map[string]any
	require.NoError(t, stored.DecodeJSON(&storedMap))
	for _, key := range []string{"default_role", "groups_claim", "group_policy_prefix"} {
		assert.NotContains(t, storedMap, key)
	}
}

// =============================================================================
// buildRoleFromFieldData all fields
// =============================================================================
