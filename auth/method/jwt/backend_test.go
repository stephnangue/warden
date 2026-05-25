// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package jwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v3"
	josejwt "github.com/go-jose/go-jose/v3/jwt"
	capjwt "github.com/hashicorp/cap/jwt"
	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// genTestPubKeyPEM generates a fresh keypair of the requested algorithm
// ("RSA" or "ECDSA") and returns the private key together with a
// PEM-encoded PKIX public key string. Used by the static-pubkey tests.
func genTestPubKeyPEM(t *testing.T, alg string) (priv crypto.PrivateKey, pemStr string) {
	t.Helper()
	var pubKey crypto.PublicKey
	switch alg {
	case "RSA":
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		priv = rsaKey
		pubKey = &rsaKey.PublicKey
	case "ECDSA":
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		priv = ecKey
		pubKey = &ecKey.PublicKey
	default:
		t.Fatalf("unsupported alg: %s", alg)
	}
	der, err := x509.MarshalPKIXPublicKey(pubKey)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	require.NotNil(t, pemBytes)
	return priv, string(pemBytes)
}

// testLogger creates a logger for tests that discards output
func testLogger() *logger.GatedLogger {
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
// Factory Tests
// =============================================================================

func TestFactory_BasicCreation(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Config: nil,
		Logger: testLogger(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)
	require.NotNil(t, backend)
}

func TestFactory_WithEmptyConfig(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Config: map[string]any{},
		Logger: testLogger(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)
	require.NotNil(t, backend)
}

func TestFactory_BackendType(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLogger(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	assert.Equal(t, "jwt", backend.Type())
}

func TestFactory_SpecialPaths(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLogger(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	paths := backend.SpecialPaths()
	require.NotNil(t, paths)
	assert.Contains(t, paths.Unauthenticated, "login")
}

// =============================================================================
// JWTAuthConfig Tests
// =============================================================================

func TestJWTAuthConfig_Defaults(t *testing.T) {
	config := &JWTAuthConfig{}
	assert.Empty(t, config.JWKSURL)
	assert.Empty(t, config.OIDCDiscoveryURL)
	assert.Empty(t, config.JWTValidationPubKeys)
}

func TestJWTAuthConfig_JWKSURL(t *testing.T) {
	config := &JWTAuthConfig{
		JWKSURL: "https://example.com/.well-known/jwks.json",
	}
	assert.Equal(t, "https://example.com/.well-known/jwks.json", config.JWKSURL)
}

func TestJWTAuthConfig_OIDCDiscoveryURL(t *testing.T) {
	config := &JWTAuthConfig{
		OIDCDiscoveryURL: "https://issuer.example.com/.well-known/openid-configuration",
	}
	assert.Equal(t, "https://issuer.example.com/.well-known/openid-configuration", config.OIDCDiscoveryURL)
}

func TestJWTAuthConfig_BoundClaims(t *testing.T) {
	config := &JWTAuthConfig{
		BoundClaims: map[string]any{
			"tenant": "acme",
			"role":   "admin",
		},
	}
	assert.Equal(t, "acme", config.BoundClaims["tenant"])
	assert.Equal(t, "admin", config.BoundClaims["role"])
}

func TestJWTAuthConfig_BoundAudiences(t *testing.T) {
	config := &JWTAuthConfig{
		BoundAudiences: []string{"aud1", "aud2"},
	}
	assert.Equal(t, []string{"aud1", "aud2"}, config.BoundAudiences)
}

func TestJWTAuthConfig_ClaimMappings(t *testing.T) {
	config := &JWTAuthConfig{
		ClaimMappings: map[string]string{
			"email": "user_email",
			"name":  "display_name",
		},
	}
	assert.Equal(t, "user_email", config.ClaimMappings["email"])
	assert.Equal(t, "display_name", config.ClaimMappings["name"])
}

// =============================================================================
// setupJWTConfig Tests
// =============================================================================

func TestSetupJWTConfig_NoKeySource(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLogger(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*jwtAuthBackend)
	err = b.setupJWTConfig(ctx, map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exactly one of")
}

func TestSetupJWTConfig_MultipleKeySources(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLogger(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*jwtAuthBackend)
	err = b.setupJWTConfig(ctx, map[string]any{
		"jwks_url":           "https://example.com/.well-known/jwks.json",
		"oidc_discovery_url": "https://issuer.example.com/.well-known/openid-configuration",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exactly one of")
}

func TestSetupJWTConfig_StaticPubKeys_ValidRSA(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{Logger: testLogger()}
	backend, err := Factory(ctx, conf)
	require.NoError(t, err)
	b := backend.(*jwtAuthBackend)

	_, pemStr := genTestPubKeyPEM(t, "RSA")

	err = b.setupJWTConfig(ctx, map[string]any{
		"jwt_validation_pubkeys": []string{pemStr},
	})
	require.NoError(t, err)
	require.NotNil(t, b.config)
	assert.NotNil(t, b.config.keySet)
	assert.NotNil(t, b.config.validator)
	assert.Equal(t, []string{pemStr}, b.config.JWTValidationPubKeys)
}

func TestSetupJWTConfig_StaticPubKeys_ValidECDSA(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{Logger: testLogger()}
	backend, err := Factory(ctx, conf)
	require.NoError(t, err)
	b := backend.(*jwtAuthBackend)

	_, pemStr := genTestPubKeyPEM(t, "ECDSA")

	err = b.setupJWTConfig(ctx, map[string]any{
		"jwt_validation_pubkeys": []string{pemStr},
	})
	require.NoError(t, err)
	assert.NotNil(t, b.config.keySet)
	assert.NotNil(t, b.config.validator)
}

func TestSetupJWTConfig_StaticPubKeys_MultipleKeys(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{Logger: testLogger()}
	backend, err := Factory(ctx, conf)
	require.NoError(t, err)
	b := backend.(*jwtAuthBackend)

	_, pem1 := genTestPubKeyPEM(t, "RSA")
	_, pem2 := genTestPubKeyPEM(t, "ECDSA")

	err = b.setupJWTConfig(ctx, map[string]any{
		"jwt_validation_pubkeys": []string{pem1, pem2},
	})
	require.NoError(t, err)
	assert.NotNil(t, b.config.keySet)
	assert.Len(t, b.config.JWTValidationPubKeys, 2)
}

func TestSetupJWTConfig_StaticPubKeys_InvalidPEM(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{Logger: testLogger()}
	backend, err := Factory(ctx, conf)
	require.NoError(t, err)
	b := backend.(*jwtAuthBackend)

	err = b.setupJWTConfig(ctx, map[string]any{
		"jwt_validation_pubkeys": []string{"not a pem"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse PEM")
	assert.Contains(t, err.Error(), "jwt_validation_pubkeys[0]")
}

func TestSetupJWTConfig_MultipleKeySources_JWKSAndPubKeys(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{Logger: testLogger()}
	backend, err := Factory(ctx, conf)
	require.NoError(t, err)
	b := backend.(*jwtAuthBackend)

	_, pemStr := genTestPubKeyPEM(t, "RSA")

	err = b.setupJWTConfig(ctx, map[string]any{
		"jwks_url":               "https://example.com/.well-known/jwks.json",
		"jwt_validation_pubkeys": []string{pemStr},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exactly one of")
}

func TestSetupJWTConfig_StaticPubKeys_StorageRoundTrip(t *testing.T) {
	b, ctx := createTestBackendWithStorage(t)

	_, pemStr := genTestPubKeyPEM(t, "RSA")
	cfg := map[string]any{
		"jwt_validation_pubkeys": []string{pemStr},
	}

	// Apply config once so in-memory state is valid before persisting.
	require.NoError(t, b.setupJWTConfig(ctx, cfg))

	entry, err := sdklogical.StorageEntryJSON("config", cfg)
	require.NoError(t, err)
	require.NoError(t, b.storageView.Put(ctx, entry))

	// Drop in-memory config and reload from storage via Initialize.
	b.configMu.Lock()
	b.config = nil
	b.configMu.Unlock()

	require.NoError(t, b.Initialize(ctx))
	require.NotNil(t, b.config)
	assert.Equal(t, []string{pemStr}, b.config.JWTValidationPubKeys)
	assert.NotNil(t, b.config.keySet)
	assert.NotNil(t, b.config.validator)
}

func TestSetupJWTConfig_JWKSURLNotReachable(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLogger(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*jwtAuthBackend)
	err = b.setupJWTConfig(ctx, map[string]any{
		"jwks_url": "http://localhost:99999/.well-known/jwks.json",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "jwks_url is not reachable")
}

func TestSetupJWTConfig_OIDCDiscoveryURLNotReachable(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLogger(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*jwtAuthBackend)
	err = b.setupJWTConfig(ctx, map[string]any{
		"oidc_discovery_url": "http://localhost:99999/.well-known/openid-configuration",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "oidc_discovery_url is not reachable")
}

// =============================================================================
// Initialize Tests
// =============================================================================

func TestInitialize_NoStorageView(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLogger(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*jwtAuthBackend)
	err = b.Initialize(ctx)
	require.NoError(t, err)
}

// =============================================================================
// Backend Interface Tests
// =============================================================================

func TestBackend_ImplementsLogicalBackend(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLogger(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	// Verify it implements the interface
	var _ logical.Backend = backend
}

func TestBackend_HasCorrectPaths(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLogger(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*jwtAuthBackend)

	// Check that paths are configured
	require.NotNil(t, b.Backend)
	require.NotEmpty(t, b.Backend.Paths)

	// We should have login and config paths
	pathPatterns := make([]string, 0)
	for _, p := range b.Backend.Paths {
		pathPatterns = append(pathPatterns, p.Pattern)
	}

	assert.Contains(t, pathPatterns, "login")
	assert.Contains(t, pathPatterns, "config")
}

func TestBackend_Class(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLogger(),
	}

	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*jwtAuthBackend)
	assert.Equal(t, logical.ClassAuth, b.Backend.BackendClass)
}

func TestSensitiveConfigFields(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{Logger: testLogger()}
	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*jwtAuthBackend)
	fields := b.SensitiveConfigFields()
	// All JWT auth config fields are public material (CA certs validate TLS
	// servers; static public keys are public by definition), so none are masked.
	assert.Empty(t, fields)
	assert.NotContains(t, fields, "oidc_discovery_ca_pem")
	assert.NotContains(t, fields, "jwks_ca_pem")
	assert.NotContains(t, fields, "jwt_validation_pubkeys")
}

// =============================================================================
// JWTRole Tests
// =============================================================================

func TestInitialize_WithStorageView(t *testing.T) {
	b, ctx := createTestBackendWithStorage(t)

	// Empty storage should succeed
	err := b.Initialize(ctx)
	require.NoError(t, err)
}

// =============================================================================
// Login with default_role from config
// =============================================================================

func TestInitialize_WithPersistedConfig(t *testing.T) {
	b, ctx := createTestBackendWithStorage(t)

	// Store a config that will fail (no reachable JWKS) - to verify Initialize tries
	configMap := map[string]any{
		"jwks_url": "http://localhost:1/.well-known/jwks.json",
	}
	entry, err := sdklogical.StorageEntryJSON("config", configMap)
	require.NoError(t, err)
	err = b.storageView.Put(ctx, entry)
	require.NoError(t, err)

	err = b.Initialize(ctx)
	// Should error because JWKS URL is not reachable
	assert.Error(t, err)
}

func testLoggerForCoverage() *logger.GatedLogger {
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
// Static-pubkey sign-and-verify integration tests
// =============================================================================

// signTestJWT mints a JWT with the given claims signed by privKey using RS256.
func signTestJWT(t *testing.T, privKey *rsa.PrivateKey, claims josejwt.Claims) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: privKey},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	require.NoError(t, err)
	token, err := josejwt.Signed(signer).Claims(claims).CompactSerialize()
	require.NoError(t, err)
	return token
}

func TestStaticPubKeys_SignAndVerify(t *testing.T) {
	ctx := context.Background()

	privAny, pemStr := genTestPubKeyPEM(t, "RSA")
	priv := privAny.(*rsa.PrivateKey)

	now := time.Now()
	token := signTestJWT(t, priv, josejwt.Claims{
		Issuer:   "test-issuer",
		Subject:  "alice",
		Audience: josejwt.Audience{"warden"},
		IssuedAt: josejwt.NewNumericDate(now),
		Expiry:   josejwt.NewNumericDate(now.Add(time.Hour)),
	})

	conf := &logical.BackendConfig{Logger: testLogger()}
	backend, err := Factory(ctx, conf)
	require.NoError(t, err)
	b := backend.(*jwtAuthBackend)

	err = b.setupJWTConfig(ctx, map[string]any{
		"jwt_validation_pubkeys": []string{pemStr},
	})
	require.NoError(t, err)

	claims, err := b.config.validator.Validate(ctx, token, capjwt.Expected{
		SigningAlgorithms: []capjwt.Alg{capjwt.RS256},
		Issuer:            "test-issuer",
		Audiences:         []string{"warden"},
	})
	require.NoError(t, err)
	assert.Equal(t, "alice", claims["sub"])
}

func TestStaticPubKeys_SignAndVerify_TamperedPayload(t *testing.T) {
	ctx := context.Background()

	privAny, pemStr := genTestPubKeyPEM(t, "RSA")
	priv := privAny.(*rsa.PrivateKey)

	now := time.Now()
	token := signTestJWT(t, priv, josejwt.Claims{
		Issuer:   "test-issuer",
		Subject:  "alice",
		Audience: josejwt.Audience{"warden"},
		IssuedAt: josejwt.NewNumericDate(now),
		Expiry:   josejwt.NewNumericDate(now.Add(time.Hour)),
	})
	// Flip one base64url character in the middle of the payload section.
	// The signature was computed over the original payload, so verification
	// must fail. (Tampering inside the signature section is unreliable: the
	// trailing base64url chars can encode padding bits and not change the
	// decoded signature.)
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3, "JWT must have three dot-separated parts")
	mid := len(parts[1]) / 2
	flip := byte('X')
	if parts[1][mid] == 'X' {
		flip = 'Y'
	}
	parts[1] = parts[1][:mid] + string(flip) + parts[1][mid+1:]
	tampered := strings.Join(parts, ".")

	conf := &logical.BackendConfig{Logger: testLogger()}
	backend, err := Factory(ctx, conf)
	require.NoError(t, err)
	b := backend.(*jwtAuthBackend)

	err = b.setupJWTConfig(ctx, map[string]any{
		"jwt_validation_pubkeys": []string{pemStr},
	})
	require.NoError(t, err)

	_, err = b.config.validator.Validate(ctx, tampered, capjwt.Expected{
		SigningAlgorithms: []capjwt.Alg{capjwt.RS256},
		Issuer:            "test-issuer",
		Audiences:         []string{"warden"},
	})
	require.Error(t, err)
}

func TestStaticPubKeys_SignAndVerify_WrongKey(t *testing.T) {
	ctx := context.Background()

	// Sign with key A.
	privAny, _ := genTestPubKeyPEM(t, "RSA")
	priv := privAny.(*rsa.PrivateKey)
	now := time.Now()
	token := signTestJWT(t, priv, josejwt.Claims{
		Issuer:   "test-issuer",
		Subject:  "alice",
		Audience: josejwt.Audience{"warden"},
		IssuedAt: josejwt.NewNumericDate(now),
		Expiry:   josejwt.NewNumericDate(now.Add(time.Hour)),
	})

	// Configure the mount with key B (different keypair).
	_, otherPEM := genTestPubKeyPEM(t, "RSA")

	conf := &logical.BackendConfig{Logger: testLogger()}
	backend, err := Factory(ctx, conf)
	require.NoError(t, err)
	b := backend.(*jwtAuthBackend)

	err = b.setupJWTConfig(ctx, map[string]any{
		"jwt_validation_pubkeys": []string{otherPEM},
	})
	require.NoError(t, err)

	_, err = b.config.validator.Validate(ctx, token, capjwt.Expected{
		SigningAlgorithms: []capjwt.Alg{capjwt.RS256},
		Issuer:            "test-issuer",
		Audiences:         []string{"warden"},
	})
	require.Error(t, err)
}
