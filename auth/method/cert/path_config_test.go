package cert

import (
	"context"
	"net/http"
	"testing"
	"time"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

func TestSetupCertConfig_InvalidPrincipalClaim(t *testing.T) {
	b, _ := createTestBackend(t)
	err := b.setupCertConfig(context.Background(), map[string]any{
		"principal_claim": "invalid",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid principal_claim")
}

func TestSetupCertConfig_InvalidRevocationMode(t *testing.T) {
	b, _ := createTestBackend(t)
	err := b.setupCertConfig(context.Background(), map[string]any{
		"revocation_mode": "invalid",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid revocation_mode")
}

func TestSetupCertConfig_InvalidCRLCacheTTL(t *testing.T) {
	b, _ := createTestBackend(t)
	err := b.setupCertConfig(context.Background(), map[string]any{
		"crl_cache_ttl": "not-a-duration",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid crl_cache_ttl")
}

func TestSetupCertConfig_InvalidOCSPTimeout(t *testing.T) {
	b, _ := createTestBackend(t)
	err := b.setupCertConfig(context.Background(), map[string]any{
		"ocsp_timeout": "not-a-duration",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid ocsp_timeout")
}

func TestSetupCertConfig_InvalidTrustedCA(t *testing.T) {
	b, _ := createTestBackend(t)
	err := b.setupCertConfig(context.Background(), map[string]any{
		"trusted_ca_pem": "not-a-pem",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no valid certificates")
}

func TestSetupCertConfig_ValidWithRevocation(t *testing.T) {
	_, _, caPEM := testCA(t)
	b, _ := createTestBackend(t)
	err := b.setupCertConfig(context.Background(), map[string]any{
		"trusted_ca_pem":  caPEM,
		"revocation_mode": "crl",
		"crl_cache_ttl":   "30m",
		"ocsp_timeout":    "10s",
	})
	require.NoError(t, err)
	assert.NotNil(t, b.revocationChecker)
}

func TestSetupCertConfig_NoRevocationChecker(t *testing.T) {
	b, _ := createTestBackend(t)
	err := b.setupCertConfig(context.Background(), map[string]any{
		"revocation_mode": "none",
	})
	require.NoError(t, err)
	assert.Nil(t, b.revocationChecker)
}

// =============================================================================
// mapToCertAuthConfig Tests
// =============================================================================

func TestMapToCertAuthConfig_TokenTTLTypes(t *testing.T) {
	t.Run("string ttl", func(t *testing.T) {
		config, err := mapToCertAuthConfig(map[string]any{
			"token_ttl": "2h",
		})
		require.NoError(t, err)
		assert.Equal(t, 2*time.Hour, config.TokenTTL)
	})

	t.Run("int ttl", func(t *testing.T) {
		config, err := mapToCertAuthConfig(map[string]any{
			"token_ttl": 3600,
		})
		require.NoError(t, err)
		assert.Equal(t, time.Hour, config.TokenTTL)
	})

	t.Run("float64 ttl", func(t *testing.T) {
		config, err := mapToCertAuthConfig(map[string]any{
			"token_ttl": float64(7200),
		})
		require.NoError(t, err)
		assert.Equal(t, 2*time.Hour, config.TokenTTL)
	})

	t.Run("duration ttl", func(t *testing.T) {
		config, err := mapToCertAuthConfig(map[string]any{
			"token_ttl": 30 * time.Minute,
		})
		require.NoError(t, err)
		assert.Equal(t, 30*time.Minute, config.TokenTTL)
	})

	t.Run("default ttl", func(t *testing.T) {
		config, err := mapToCertAuthConfig(map[string]any{})
		require.NoError(t, err)
		assert.Equal(t, time.Hour, config.TokenTTL)
	})

	t.Run("default principal_claim", func(t *testing.T) {
		config, err := mapToCertAuthConfig(map[string]any{})
		require.NoError(t, err)
		assert.Equal(t, "cn", config.PrincipalClaim)
	})
}

// =============================================================================
// parsePEMCertificates Tests
// =============================================================================

func TestHandleConfigRead_NilConfig(t *testing.T) {
	b, ctx := createTestBackend(t)
	b.config = nil

	resp, err := b.handleConfigRead(ctx, &logical.Request{}, &framework.FieldData{})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Empty(t, resp.Data)
}

func TestHandleConfigRead_WithConfig(t *testing.T) {
	_, _, caPEM := testCA(t)
	b, ctx := createTestBackend(t)
	b.config = &CertAuthConfig{
		TrustedCAPEM:   caPEM,
		PrincipalClaim: "cn",
		TokenTTL:       time.Hour,
		RevocationMode: "none",
		DefaultRole:    "default",
	}

	resp, err := b.handleConfigRead(ctx, &logical.Request{}, &framework.FieldData{})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "cn", resp.Data["principal_claim"])
	assert.Equal(t, "default", resp.Data["default_role"])
	assert.Equal(t, 1, resp.Data["trusted_ca_count"])
}

// =============================================================================
// handleConfigWrite Tests
// =============================================================================

func TestHandleConfigWrite_Success(t *testing.T) {
	_, _, caPEM := testCA(t)
	b, ctx := createTestBackend(t)

	d := &framework.FieldData{
		Raw: map[string]any{
			"trusted_ca_pem":  caPEM,
			"principal_claim": "cn",
			"token_ttl":       3600,
		},
		Schema: b.pathConfig().Fields,
	}

	resp, err := b.handleConfigWrite(ctx, &logical.Request{}, d)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.NotNil(t, b.config)
}

func TestHandleConfigWrite_InvalidConfig(t *testing.T) {
	b, ctx := createTestBackend(t)

	d := &framework.FieldData{
		Raw: map[string]any{
			"principal_claim": "invalid_claim",
		},
		Schema: b.pathConfig().Fields,
	}

	resp, err := b.handleConfigWrite(ctx, &logical.Request{}, d)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// =============================================================================
// Role CRUD Tests
// =============================================================================

func TestHandleConfigWrite_PersistsToStorage(t *testing.T) {
	_, _, caPEM := testCA(t)
	b, ctx := createTestBackend(t)

	d := &framework.FieldData{
		Raw: map[string]any{
			"trusted_ca_pem":  caPEM,
			"principal_claim": "cn",
			"token_ttl":       3600,
			"default_role":    "my-role",
		},
		Schema: b.pathConfig().Fields,
	}

	resp, err := b.handleConfigWrite(ctx, &logical.Request{}, d)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify persisted to storage
	entry, err := b.storageView.Get(ctx, "config")
	require.NoError(t, err)
	assert.NotNil(t, entry)
}

func TestHandleConfigWrite_MergesWithExisting(t *testing.T) {
	_, _, caPEM := testCA(t)
	b, ctx := createTestBackend(t)

	// Set initial config
	b.config = &CertAuthConfig{
		TrustedCAPEM:   caPEM,
		PrincipalClaim: "cn",
		TokenTTL:       time.Hour,
	}
	b.config.caPool, _ = buildCAPool(caPEM)

	// Update only default_role
	d := &framework.FieldData{
		Raw: map[string]any{
			"default_role": "new-default",
		},
		Schema: b.pathConfig().Fields,
	}

	resp, err := b.handleConfigWrite(ctx, &logical.Request{}, d)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "new-default", b.config.DefaultRole)
}

