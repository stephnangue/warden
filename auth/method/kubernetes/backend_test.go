package kubernetes

import (
	"context"
	"testing"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/logical"
)

func TestFactory_BasicCreation(t *testing.T) {
	be, err := Factory(context.Background(), &logical.BackendConfig{Logger: testLogger()})
	require.NoError(t, err)
	require.NotNil(t, be)
}

func TestFactory_WithEmptyConfig(t *testing.T) {
	be, err := Factory(context.Background(), &logical.BackendConfig{
		Logger: testLogger(),
		Config: map[string]any{},
	})
	require.NoError(t, err)
	require.NotNil(t, be)
}

func TestFactory_BackendType(t *testing.T) {
	be, err := Factory(context.Background(), &logical.BackendConfig{Logger: testLogger()})
	require.NoError(t, err)
	assert.Equal(t, "kubernetes", be.Type())
}

func TestFactory_SpecialPathsUnauthenticated(t *testing.T) {
	be, err := Factory(context.Background(), &logical.BackendConfig{Logger: testLogger()})
	require.NoError(t, err)
	paths := be.SpecialPaths()
	require.NotNil(t, paths)
	assert.Contains(t, paths.Unauthenticated, "login")
	assert.Contains(t, paths.Unauthenticated, "introspect/roles")
}

func TestFactory_SensitiveConfigFields(t *testing.T) {
	be, err := Factory(context.Background(), &logical.BackendConfig{Logger: testLogger()})
	require.NoError(t, err)
	provider, ok := be.(logical.SensitiveFieldsProvider)
	require.True(t, ok, "kubernetes backend must implement SensitiveFieldsProvider")
	assert.Equal(t, []string{"token_reviewer_jwt"}, provider.SensitiveConfigFields())
}

func TestSetupConfig_RequiresKubernetesHost(t *testing.T) {
	b, ctx := newTestBackend(t)
	err := b.setupConfig(ctx, map[string]any{
		"kubernetes_ca_cert": "PEM",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "kubernetes_host is required")
}

func TestSetupConfig_RequiresCAUnlessSkipVerify(t *testing.T) {
	b, ctx := newTestBackend(t)
	err := b.setupConfig(ctx, map[string]any{
		"kubernetes_host": "https://kube",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "kubernetes_ca_cert is required")

	require.NoError(t, b.setupConfig(ctx, map[string]any{
		"kubernetes_host": "https://kube",
		"tls_skip_verify": true,
	}))
}

func TestInitialize_RoundTripsConfigFromStorage(t *testing.T) {
	b, ctx := newTestBackend(t)

	// Write config directly to storage (the persisted shape produced by
	// handleConfigWrite: token_ttl as string, all fields populated).
	stored := map[string]any{
		"kubernetes_host":    "https://kube.example.com",
		"tls_skip_verify":    true,
		"token_reviewer_jwt": "reviewer-jwt",
		"issuer":             "https://kubernetes.default.svc",
		"token_ttl":          "45m",
		"default_role":       "ops-reader",
	}
	entry, err := sdklogical.StorageEntryJSON("config", stored)
	require.NoError(t, err)
	require.NoError(t, b.storageView.Put(ctx, entry))

	// Drop in-memory config and reload via Initialize.
	b.configMu.Lock()
	b.config = nil
	b.configMu.Unlock()
	require.NoError(t, b.Initialize(ctx))
	require.NotNil(t, b.config)
	assert.Equal(t, "https://kube.example.com", b.config.KubernetesHost)
	assert.True(t, b.config.TLSSkipVerify)
	assert.Equal(t, "reviewer-jwt", b.config.TokenReviewerJWT)
	assert.Equal(t, "https://kubernetes.default.svc", b.config.Issuer)
	assert.Equal(t, "ops-reader", b.config.DefaultRole)
	assert.NotNil(t, b.config.httpClient, "Initialize must rebuild the HTTP client")
}

func TestInitialize_NoStoredConfigIsNotAnError(t *testing.T) {
	b, ctx := newTestBackend(t)
	// Fresh backend with empty storage — Initialize should succeed and
	// leave b.config nil (the kubernetes auth method is "not configured yet").
	require.NoError(t, b.Initialize(ctx))
	assert.Nil(t, b.config)
}
