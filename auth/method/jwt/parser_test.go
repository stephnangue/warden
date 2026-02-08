// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package jwt

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// mapToJWTAuthConfig Tests
// =============================================================================

func TestMapToJWTAuthConfig_BasicJWTMode(t *testing.T) {
	data := map[string]any{
		"mode":     "jwt",
		"jwks_url": "https://example.com/.well-known/jwks.json",
	}

	config, err := mapToJWTAuthConfig(data)
	require.NoError(t, err)

	assert.Equal(t, "jwt", config.Mode)
	assert.Equal(t, "https://example.com/.well-known/jwks.json", config.JWKSURL)
}

func TestMapToJWTAuthConfig_BasicOIDCMode(t *testing.T) {
	data := map[string]any{
		"mode":               "oidc",
		"oidc_discovery_url": "https://issuer.example.com/.well-known/openid-configuration",
	}

	config, err := mapToJWTAuthConfig(data)
	require.NoError(t, err)

	assert.Equal(t, "oidc", config.Mode)
	assert.Equal(t, "https://issuer.example.com/.well-known/openid-configuration", config.OIDCDiscoveryURL)
}

func TestMapToJWTAuthConfig_DefaultValues(t *testing.T) {
	data := map[string]any{
		"mode":     "jwt",
		"jwks_url": "https://example.com/.well-known/jwks.json",
	}

	config, err := mapToJWTAuthConfig(data)
	require.NoError(t, err)

	// Check default values
	assert.Equal(t, "sub", config.UserClaim)
	assert.Equal(t, 1*time.Hour, config.TokenTTL)
}

func TestMapToJWTAuthConfig_CustomTokenTTL(t *testing.T) {
	data := map[string]any{
		"mode":      "jwt",
		"jwks_url":  "https://example.com/.well-known/jwks.json",
		"token_ttl": "2h",
	}

	config, err := mapToJWTAuthConfig(data)
	require.NoError(t, err)

	assert.Equal(t, 2*time.Hour, config.TokenTTL)
}

func TestMapToJWTAuthConfig_CustomUserClaim(t *testing.T) {
	data := map[string]any{
		"mode":       "jwt",
		"jwks_url":   "https://example.com/.well-known/jwks.json",
		"user_claim": "email",
	}

	config, err := mapToJWTAuthConfig(data)
	require.NoError(t, err)

	assert.Equal(t, "email", config.UserClaim)
}

func TestMapToJWTAuthConfig_BoundIssuer(t *testing.T) {
	data := map[string]any{
		"mode":         "jwt",
		"jwks_url":     "https://example.com/.well-known/jwks.json",
		"bound_issuer": "https://issuer.example.com",
	}

	config, err := mapToJWTAuthConfig(data)
	require.NoError(t, err)

	assert.Equal(t, "https://issuer.example.com", config.BoundIssuer)
}

func TestMapToJWTAuthConfig_BoundAudiences(t *testing.T) {
	data := map[string]any{
		"mode":            "jwt",
		"jwks_url":        "https://example.com/.well-known/jwks.json",
		"bound_audiences": []string{"aud1", "aud2", "aud3"},
	}

	config, err := mapToJWTAuthConfig(data)
	require.NoError(t, err)

	assert.Equal(t, []string{"aud1", "aud2", "aud3"}, config.BoundAudiences)
}

func TestMapToJWTAuthConfig_BoundSubject(t *testing.T) {
	data := map[string]any{
		"mode":          "jwt",
		"jwks_url":      "https://example.com/.well-known/jwks.json",
		"bound_subject": "expected-subject",
	}

	config, err := mapToJWTAuthConfig(data)
	require.NoError(t, err)

	assert.Equal(t, "expected-subject", config.BoundSubject)
}

func TestMapToJWTAuthConfig_BoundClaims(t *testing.T) {
	data := map[string]any{
		"mode":     "jwt",
		"jwks_url": "https://example.com/.well-known/jwks.json",
		"bound_claims": map[string]any{
			"tenant": "acme",
			"role":   "admin",
		},
	}

	config, err := mapToJWTAuthConfig(data)
	require.NoError(t, err)

	require.NotNil(t, config.BoundClaims)
	assert.Equal(t, "acme", config.BoundClaims["tenant"])
	assert.Equal(t, "admin", config.BoundClaims["role"])
}

func TestMapToJWTAuthConfig_ClaimMappings(t *testing.T) {
	data := map[string]any{
		"mode":     "jwt",
		"jwks_url": "https://example.com/.well-known/jwks.json",
		"claim_mappings": map[string]string{
			"preferred_username": "username",
			"email":              "user_email",
		},
	}

	config, err := mapToJWTAuthConfig(data)
	require.NoError(t, err)

	require.NotNil(t, config.ClaimMappings)
	assert.Equal(t, "username", config.ClaimMappings["preferred_username"])
	assert.Equal(t, "user_email", config.ClaimMappings["email"])
}

func TestMapToJWTAuthConfig_GroupsClaim(t *testing.T) {
	data := map[string]any{
		"mode":         "jwt",
		"jwks_url":     "https://example.com/.well-known/jwks.json",
		"groups_claim": "roles",
	}

	config, err := mapToJWTAuthConfig(data)
	require.NoError(t, err)

	assert.Equal(t, "roles", config.GroupsClaim)
}

func TestMapToJWTAuthConfig_WithCACerts(t *testing.T) {
	data := map[string]any{
		"mode":                 "oidc",
		"oidc_discovery_url":   "https://issuer.example.com/.well-known/openid-configuration",
		"oidc_discovery_ca_pem": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----",
	}

	config, err := mapToJWTAuthConfig(data)
	require.NoError(t, err)

	assert.Equal(t, "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----", config.OIDCDiscoveryCA)
}

func TestMapToJWTAuthConfig_JWKSWithCA(t *testing.T) {
	data := map[string]any{
		"mode":        "jwt",
		"jwks_url":    "https://example.com/.well-known/jwks.json",
		"jwks_ca_pem": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----",
	}

	config, err := mapToJWTAuthConfig(data)
	require.NoError(t, err)

	assert.Equal(t, "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----", config.JWKSCA)
}

func TestMapToJWTAuthConfig_EmptyMap(t *testing.T) {
	data := map[string]any{}

	config, err := mapToJWTAuthConfig(data)
	require.NoError(t, err)

	// Should have default values
	assert.Equal(t, "sub", config.UserClaim)
	assert.Equal(t, 1*time.Hour, config.TokenTTL)
}

func TestMapToJWTAuthConfig_AllFields(t *testing.T) {
	data := map[string]any{
		"mode":                   "jwt",
		"jwks_url":               "https://example.com/.well-known/jwks.json",
		"jwks_ca_pem":            "cert-content",
		"bound_issuer":           "https://issuer.example.com",
		"bound_audiences":        []string{"aud1"},
		"bound_subject":          "expected-sub",
		"bound_claims":           map[string]any{"claim1": "value1"},
		"claim_mappings":         map[string]string{"c1": "m1"},
		"user_claim":             "email",
		"groups_claim":           "roles",
		"token_ttl":              "4h",
	}

	config, err := mapToJWTAuthConfig(data)
	require.NoError(t, err)

	assert.Equal(t, "jwt", config.Mode)
	assert.Equal(t, "https://example.com/.well-known/jwks.json", config.JWKSURL)
	assert.Equal(t, "cert-content", config.JWKSCA)
	assert.Equal(t, "https://issuer.example.com", config.BoundIssuer)
	assert.Equal(t, []string{"aud1"}, config.BoundAudiences)
	assert.Equal(t, "expected-sub", config.BoundSubject)
	assert.Equal(t, "value1", config.BoundClaims["claim1"])
	assert.Equal(t, "m1", config.ClaimMappings["c1"])
	assert.Equal(t, "email", config.UserClaim)
	assert.Equal(t, "roles", config.GroupsClaim)
	assert.Equal(t, 4*time.Hour, config.TokenTTL)
}

// =============================================================================
// Duration Parsing Tests
// =============================================================================

func TestMapToJWTAuthConfig_DurationParsing(t *testing.T) {
	tests := []struct {
		name            string
		tokenTTL        string
		expectedTTL     time.Duration
	}{
		{"Seconds", "30s", 30 * time.Second},
		{"Minutes", "10m", 10 * time.Minute},
		{"Hours", "2h", 2 * time.Hour},
		{"Complex", "1h30m", 90 * time.Minute},
		{"Days as hours", "24h", 24 * time.Hour},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := map[string]any{
				"mode":      "jwt",
				"jwks_url":  "https://example.com/.well-known/jwks.json",
				"token_ttl": tc.tokenTTL,
			}

			config, err := mapToJWTAuthConfig(data)
			require.NoError(t, err)
			assert.Equal(t, tc.expectedTTL, config.TokenTTL)
		})
	}
}

func TestMapToJWTAuthConfig_DurationAsNumber(t *testing.T) {
	// Duration passed as number (nanoseconds in Go)
	data := map[string]any{
		"mode":      "jwt",
		"jwks_url":  "https://example.com/.well-known/jwks.json",
		"token_ttl": time.Hour, // duration directly
	}

	config, err := mapToJWTAuthConfig(data)
	require.NoError(t, err)
	assert.Equal(t, time.Hour, config.TokenTTL)
}

// =============================================================================
// Error Cases
// =============================================================================

func TestMapToJWTAuthConfig_InvalidJSON(t *testing.T) {
	// Create an unmarshallable value
	data := map[string]any{
		"mode":     "jwt",
		"jwks_url": func() {}, // Functions can't be marshaled to JSON
	}

	_, err := mapToJWTAuthConfig(data)
	assert.Error(t, err)
}

// =============================================================================
// Mode Inference Tests
// =============================================================================

func TestMapToJWTAuthConfig_ModeRequired(t *testing.T) {
	// Mode is no longer inferred - it must be explicitly specified
	// The validation happens in setupJWTConfig, not mapToJWTAuthConfig
	data := map[string]any{
		"mode":     "jwt",
		"jwks_url": "https://example.com/jwks",
	}

	config, err := mapToJWTAuthConfig(data)
	require.NoError(t, err)
	assert.Equal(t, "jwt", config.Mode)
}
