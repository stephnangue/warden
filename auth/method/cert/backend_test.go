// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package cert

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
	"math/big"
	"net/http"
	"time"
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
// TTL
// =============================================================================

// The TTL is the mount's token_ttl capped by the certificate's NotAfter.
func TestCalculateTTL(t *testing.T) {
	caCert, caKey, _ := testCA(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(30 * time.Minute),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	cert, _ := x509.ParseCertificate(certDER)
	now := time.Now()

	ttl := calculateTTL(&CertAuthConfig{TokenTTL: 2 * time.Hour}, cert, now)
	assert.Less(t, ttl, 31*time.Minute, "capped by the certificate's validity")
	assert.Greater(t, ttl, 28*time.Minute)

	assert.Equal(t, 10*time.Minute, calculateTTL(&CertAuthConfig{TokenTTL: 10 * time.Minute}, cert, now), "capped by token_ttl")
	assert.Greater(t, calculateTTL(nil, cert, now), 28*time.Minute, "no config: no cap from the mount")
	assert.Equal(t, time.Duration(0), calculateTTL(&CertAuthConfig{TokenTTL: time.Hour}, cert, cert.NotAfter.Add(time.Second)))
}

// =============================================================================
// Login
// =============================================================================

// loginWith runs a login presenting cert against b.
func loginWith(t *testing.T, b *certAuthBackend, cert *x509.Certificate) *logical.Response {
	t.Helper()
	resp, err := b.handleLogin(context.Background(), &logical.Request{HTTPRequest: newCertHTTPRequest(t, cert)},
		&framework.FieldData{Raw: map[string]any{}, Schema: b.pathLogin().Fields})
	require.NoError(t, err)
	require.NotNil(t, resp)
	return resp
}

// trustingBackend returns a backend whose mount config trusts caPEM.
func trustingBackend(t *testing.T, caPEM string) *certAuthBackend {
	t.Helper()
	b, _ := createTestBackend(t)
	b.config = &CertAuthConfig{
		TrustedCAPEM:   caPEM,
		PrincipalClaim: "cn",
		TokenTTL:       time.Hour,
	}
	b.config.caPool, _ = buildCAPool(caPEM)
	return b
}

func TestHandleLogin_NoCert(t *testing.T) {
	b, ctx := createTestBackend(t)
	b.config = &CertAuthConfig{PrincipalClaim: "cn"}

	req := &logical.Request{
		HTTPRequest: nil, // no HTTP request
	}
	d := &framework.FieldData{
		Raw:    map[string]any{},
		Schema: b.pathLogin().Fields,
	}

	resp, err := b.handleLogin(ctx, req, d)
	require.NoError(t, err)
	assert.NotNil(t, resp.Err)
	assert.Contains(t, resp.Err.Error(), "no client certificate")
}

// A login admits any certificate that chains to the mount's trusted CAs:
// which ones get a role is the groups' decision.
func TestHandleLogin_FullFlow_Success(t *testing.T) {
	caCert, caKey, caPEM := testCA(t)
	clientCert := testClientCert(t, caCert, caKey, "test-agent")
	b := trustingBackend(t, caPEM)

	resp := loginWith(t, b, clientCert)
	assert.Nil(t, resp.Err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	require.NotNil(t, resp.Auth)
	assert.Equal(t, "test-agent", resp.Auth.PrincipalID)
	assert.Equal(t, "cert_role", resp.Auth.TokenType)
	assert.Nil(t, resp.Auth.Policies, "a login is an admission: no policies")
	assert.Nil(t, resp.Auth.Metadata, "a login is an admission: no metadata")
	assert.Equal(t, certFingerprint(clientCert), resp.Auth.ClientToken)
	assert.LessOrEqual(t, resp.Auth.TokenTTL, time.Hour)
	require.NotNil(t, resp.Auth.Admission)
	assert.Same(t, b.mountFacts, resp.Auth.Admission.Mount)
	assert.NotContains(t, resp.Data, "role")
}

func TestHandleLogin_CertVerificationFails(t *testing.T) {
	_, _, caPEM := testCA(t)
	// Create a client cert signed by a DIFFERENT CA
	otherCACert, otherCAKey, _ := testCA(t)
	clientCert := testClientCert(t, otherCACert, otherCAKey, "test-agent")
	b := trustingBackend(t, caPEM)

	resp := loginWith(t, b, clientCert)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Nil(t, resp.Auth)
}

func TestHandleLogin_NoCAPool(t *testing.T) {
	caCert, caKey, _ := testCA(t)
	clientCert := testClientCert(t, caCert, caKey, "test-agent")

	b, _ := createTestBackend(t)
	b.config = &CertAuthConfig{
		PrincipalClaim: "cn",
		TokenTTL:       time.Hour,
		// No TrustedCAPEM -> no caPool
	}

	resp := loginWith(t, b, clientCert)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)

	b.config = nil
	resp = loginWith(t, b, clientCert)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode, "an unconfigured mount cannot decide")
}

// A role's CA no longer widens the mount: only the mount's trusted CAs admit.
func TestHandleLogin_OnlyTheMountPoolAdmits(t *testing.T) {
	caCert, caKey, caPEM := testCA(t)
	clientCert := testClientCert(t, caCert, caKey, "test-agent")

	b, ctx := createTestBackend(t)
	b.config = &CertAuthConfig{PrincipalClaim: "cn", TokenTTL: time.Hour}
	require.NoError(t, b.setRole(ctx, &CertRole{
		Name:        "test-role",
		Certificate: caPEM, // a role CA, left in storage from before
		TokenTTL:    time.Hour.String(),
		TokenType:   "cert_role",
	}))

	resp := loginWith(t, b, clientCert)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode, "no mount CA: the mount cannot decide")
}

func TestHandleLogin_MountPrincipalClaim(t *testing.T) {
	caCert, caKey, caPEM := testCA(t)
	clientCert := testClientCert(t, caCert, caKey, "test-agent")
	b := trustingBackend(t, caPEM)
	b.config.PrincipalClaim = "serial"

	resp := loginWith(t, b, clientCert)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	// Serial number should be the principal
	assert.Equal(t, clientCert.SerialNumber.String(), resp.Auth.PrincipalID)

	b.config.PrincipalClaim = "dns_san"
	resp = loginWith(t, b, clientCert)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "no principal under principal_claim")
}

// =============================================================================
// getCAPool Tests
// =============================================================================

func TestGetCAPool_RoleSpecific(t *testing.T) {
	_, _, caPEM := testCA(t)
	b, _ := createTestBackend(t)
	b.config = nil

	role := &CertRole{Certificate: caPEM}
	pool, err := getCAPool(b.config, role)
	require.NoError(t, err)
	assert.NotNil(t, pool)
}

func TestGetCAPool_GlobalConfig(t *testing.T) {
	_, _, caPEM := testCA(t)
	b, _ := createTestBackend(t)
	caPool, _ := buildCAPool(caPEM)
	b.config = &CertAuthConfig{caPool: caPool}

	role := &CertRole{}
	pool, err := getCAPool(b.config, role)
	require.NoError(t, err)
	assert.NotNil(t, pool)
}

func TestGetCAPool_None(t *testing.T) {
	b, _ := createTestBackend(t)
	b.config = &CertAuthConfig{}

	role := &CertRole{}
	pool, err := getCAPool(b.config, role)
	require.NoError(t, err)
	assert.Nil(t, pool)
}

// =============================================================================
// buildRoleFromFieldData with all fields
// =============================================================================
