// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package cert

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/logical"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"time"
	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/framework"
)

// =============================================================================
// Factory Tests
// =============================================================================

func TestFactory_BasicCreation(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
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
	assert.Equal(t, "cert", backend.Type())
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

func TestSensitiveConfigFields(t *testing.T) {
	b, _ := createTestBackend(t)
	fields := b.SensitiveConfigFields()
	assert.Contains(t, fields, "trusted_ca_pem")
}

// =============================================================================
// Initialize Tests
// =============================================================================

func TestInitialize_NilStorageView(t *testing.T) {
	ctx := context.Background()
	conf := &logical.BackendConfig{
		Logger: testLogger(),
	}
	backend, err := Factory(ctx, conf)
	require.NoError(t, err)

	b := backend.(*certAuthBackend)
	b.storageView = nil

	err = b.Initialize(ctx)
	require.NoError(t, err)
}

func TestInitialize_EmptyStorage(t *testing.T) {
	b, ctx := createTestBackend(t)
	err := b.Initialize(ctx)
	require.NoError(t, err)
}

func TestInitialize_WithPersistedConfig(t *testing.T) {
	b, ctx := createTestBackend(t)

	_, _, caPEM := testCA(t)

	// Persist config to storage
	configMap := map[string]any{
		"trusted_ca_pem":  caPEM,
		"principal_claim": "cn",
		"token_ttl":       "2h",
	}
	entry, err := sdklogical.StorageEntryJSON("config", configMap)
	require.NoError(t, err)
	err = b.storageView.Put(ctx, entry)
	require.NoError(t, err)

	err = b.Initialize(ctx)
	require.NoError(t, err)
	assert.NotNil(t, b.config)
	assert.Equal(t, "cn", b.config.PrincipalClaim)
}

// =============================================================================
// setupCertConfig Tests
// =============================================================================

func TestCalculateTTL(t *testing.T) {
	_, caKey, caPEM := testCA(t)
	caCert, _ := buildCAPool(caPEM)
	_ = caCert

	b, _ := createTestBackend(t)
	b.config = &CertAuthConfig{
		TokenTTL: 2 * time.Hour,
	}

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	// CA for signing
	caSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	caTemplate := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: "CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)

	// Client cert valid for 30 minutes
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(30 * time.Minute),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	cert, _ := x509.ParseCertificate(certDER)

	role := &CertRole{TokenTTL: "1h"}

	ttl := b.calculateTTL(cert, role)
	// Should be capped by cert validity (~30min), not role (1h) or config (2h)
	assert.Less(t, ttl, 31*time.Minute)
	assert.Greater(t, ttl, 28*time.Minute)
}

// =============================================================================
// extractPrincipal edge cases
// =============================================================================

func TestHandleLogin_NoCert(t *testing.T) {
	b, ctx := createTestBackend(t)
	b.config = &CertAuthConfig{PrincipalClaim: "cn"}

	req := &logical.Request{
		HTTPRequest: nil, // no HTTP request
	}
	d := &framework.FieldData{
		Raw:    map[string]any{"role": "test"},
		Schema: b.pathLogin().Fields,
	}

	resp, err := b.handleLogin(ctx, req, d)
	require.NoError(t, err)
	assert.NotNil(t, resp.Err)
	assert.Contains(t, resp.Err.Error(), "no client certificate")
}

// =============================================================================
// matchesAnyGlob Tests
// =============================================================================

func TestHandleLogin_FullFlow_Success(t *testing.T) {
	caCert, caKey, caPEM := testCA(t)
	clientCert := testClientCert(t, caCert, caKey, "test-agent")

	b, ctx := createTestBackend(t)
	b.config = &CertAuthConfig{
		TrustedCAPEM:   caPEM,
		PrincipalClaim: "cn",
		TokenTTL:       time.Hour,
	}
	b.config.caPool, _ = buildCAPool(caPEM)

	// Create a role
	role := &CertRole{
		Name:               "test-role",
		AllowedCommonNames: []string{"test-*"},
		TokenPolicies:      []string{"default", "read"},
		TokenTTL:           time.Hour.String(),
		TokenType:          "cert_role",
	}
	err := b.setRole(ctx, role)
	require.NoError(t, err)

	req := &logical.Request{
		HTTPRequest: newCertHTTPRequest(t, clientCert),
	}
	d := &framework.FieldData{
		Raw:    map[string]any{"role": "test-role"},
		Schema: b.pathLogin().Fields,
	}

	resp, err := b.handleLogin(ctx, req, d)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Nil(t, resp.Err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.NotNil(t, resp.Auth)
	assert.Equal(t, "test-agent", resp.Auth.PrincipalID)
	assert.Equal(t, "test-role", resp.Auth.RoleName)
	assert.Equal(t, []string{"default", "read"}, resp.Auth.Policies)
}

func TestHandleLogin_RoleNotFound(t *testing.T) {
	caCert, caKey, caPEM := testCA(t)
	clientCert := testClientCert(t, caCert, caKey, "test-agent")

	b, ctx := createTestBackend(t)
	b.config = &CertAuthConfig{
		TrustedCAPEM:   caPEM,
		PrincipalClaim: "cn",
		TokenTTL:       time.Hour,
	}
	b.config.caPool, _ = buildCAPool(caPEM)

	req := &logical.Request{
		HTTPRequest: newCertHTTPRequest(t, clientCert),
	}
	d := &framework.FieldData{
		Raw:    map[string]any{"role": "nonexistent"},
		Schema: b.pathLogin().Fields,
	}

	resp, err := b.handleLogin(ctx, req, d)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestHandleLogin_CertVerificationFails(t *testing.T) {
	caCert, caKey, caPEM := testCA(t)
	// Create a client cert signed by a DIFFERENT CA
	otherCACert, otherCAKey, _ := testCA(t)
	clientCert := testClientCert(t, otherCACert, otherCAKey, "test-agent")

	b, ctx := createTestBackend(t)
	b.config = &CertAuthConfig{
		TrustedCAPEM:   caPEM,
		PrincipalClaim: "cn",
		TokenTTL:       time.Hour,
	}
	b.config.caPool, _ = buildCAPool(caPEM)
	_ = caCert
	_ = caKey

	role := &CertRole{
		Name:               "test-role",
		AllowedCommonNames: []string{"test-*"},
		TokenTTL:           time.Hour.String(),
		TokenType:          "cert_role",
	}
	err := b.setRole(ctx, role)
	require.NoError(t, err)

	req := &logical.Request{
		HTTPRequest: newCertHTTPRequest(t, clientCert),
	}
	d := &framework.FieldData{
		Raw:    map[string]any{"role": "test-role"},
		Schema: b.pathLogin().Fields,
	}

	resp, err := b.handleLogin(ctx, req, d)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestHandleLogin_ConstraintMismatch(t *testing.T) {
	caCert, caKey, caPEM := testCA(t)
	clientCert := testClientCert(t, caCert, caKey, "wrong-agent")

	b, ctx := createTestBackend(t)
	b.config = &CertAuthConfig{
		TrustedCAPEM:   caPEM,
		PrincipalClaim: "cn",
		TokenTTL:       time.Hour,
	}
	b.config.caPool, _ = buildCAPool(caPEM)

	role := &CertRole{
		Name:               "test-role",
		AllowedCommonNames: []string{"allowed-*"},
		TokenTTL:           time.Hour.String(),
		TokenType:          "cert_role",
	}
	err := b.setRole(ctx, role)
	require.NoError(t, err)

	req := &logical.Request{
		HTTPRequest: newCertHTTPRequest(t, clientCert),
	}
	d := &framework.FieldData{
		Raw:    map[string]any{"role": "test-role"},
		Schema: b.pathLogin().Fields,
	}

	resp, err := b.handleLogin(ctx, req, d)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestHandleLogin_NoCAPool(t *testing.T) {
	caCert, caKey, _ := testCA(t)
	clientCert := testClientCert(t, caCert, caKey, "test-agent")

	b, ctx := createTestBackend(t)
	b.config = &CertAuthConfig{
		PrincipalClaim: "cn",
		TokenTTL:       time.Hour,
		// No TrustedCAPEM -> no caPool
	}

	role := &CertRole{
		Name:               "test-role",
		AllowedCommonNames: []string{"test-*"},
		TokenTTL:           time.Hour.String(),
		TokenType:          "cert_role",
	}
	err := b.setRole(ctx, role)
	require.NoError(t, err)

	req := &logical.Request{
		HTTPRequest: newCertHTTPRequest(t, clientCert),
	}
	d := &framework.FieldData{
		Raw:    map[string]any{"role": "test-role"},
		Schema: b.pathLogin().Fields,
	}

	resp, err := b.handleLogin(ctx, req, d)
	require.NoError(t, err)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

func TestHandleLogin_RoleSpecificCA(t *testing.T) {
	caCert, caKey, caPEM := testCA(t)
	clientCert := testClientCert(t, caCert, caKey, "test-agent")

	b, ctx := createTestBackend(t)
	b.config = &CertAuthConfig{
		PrincipalClaim: "cn",
		TokenTTL:       time.Hour,
		// No global CA
	}

	role := &CertRole{
		Name:               "test-role",
		AllowedCommonNames: []string{"test-*"},
		Certificate:        caPEM, // Role-specific CA
		TokenTTL:           time.Hour.String(),
		TokenType:          "cert_role",
		TokenPolicies:      []string{"default"},
	}
	err := b.setRole(ctx, role)
	require.NoError(t, err)

	req := &logical.Request{
		HTTPRequest: newCertHTTPRequest(t, clientCert),
	}
	d := &framework.FieldData{
		Raw:    map[string]any{"role": "test-role"},
		Schema: b.pathLogin().Fields,
	}

	resp, err := b.handleLogin(ctx, req, d)
	require.NoError(t, err)
	assert.Nil(t, resp.Err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestHandleLogin_PrincipalClaimOverride(t *testing.T) {
	caCert, caKey, caPEM := testCA(t)
	clientCert := testClientCert(t, caCert, caKey, "test-agent")

	b, ctx := createTestBackend(t)
	b.config = &CertAuthConfig{
		TrustedCAPEM:   caPEM,
		PrincipalClaim: "cn",
		TokenTTL:       time.Hour,
	}
	b.config.caPool, _ = buildCAPool(caPEM)

	role := &CertRole{
		Name:               "test-role",
		AllowedCommonNames: []string{"test-*"},
		TokenTTL:           time.Hour.String(),
		TokenType:          "cert_role",
		PrincipalClaim:     "serial", // Override
	}
	err := b.setRole(ctx, role)
	require.NoError(t, err)

	req := &logical.Request{
		HTTPRequest: newCertHTTPRequest(t, clientCert),
	}
	d := &framework.FieldData{
		Raw:    map[string]any{"role": "test-role"},
		Schema: b.pathLogin().Fields,
	}

	resp, err := b.handleLogin(ctx, req, d)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	// Serial number should be the principal
	assert.NotEqual(t, "test-agent", resp.Auth.PrincipalID)
	assert.NotEmpty(t, resp.Auth.PrincipalID)
}

// =============================================================================
// getCAPool Tests
// =============================================================================

func TestGetCAPool_RoleSpecific(t *testing.T) {
	_, _, caPEM := testCA(t)
	b, _ := createTestBackend(t)
	b.config = nil

	role := &CertRole{Certificate: caPEM}
	pool, err := b.getCAPool(role)
	require.NoError(t, err)
	assert.NotNil(t, pool)
}

func TestGetCAPool_GlobalConfig(t *testing.T) {
	_, _, caPEM := testCA(t)
	b, _ := createTestBackend(t)
	caPool, _ := buildCAPool(caPEM)
	b.config = &CertAuthConfig{caPool: caPool}

	role := &CertRole{}
	pool, err := b.getCAPool(role)
	require.NoError(t, err)
	assert.NotNil(t, pool)
}

func TestGetCAPool_None(t *testing.T) {
	b, _ := createTestBackend(t)
	b.config = &CertAuthConfig{}

	role := &CertRole{}
	pool, err := b.getCAPool(role)
	require.NoError(t, err)
	assert.Nil(t, pool)
}

// =============================================================================
// buildRoleFromFieldData with all fields
// =============================================================================
