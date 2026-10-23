package cert

import (
	"context"
	"crypto/x509"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/logical"
)

// createTestBackend creates a cert backend for testing.
func createTestBackend(t *testing.T) (*certAuthBackend, context.Context) {
	t.Helper()
	ctx := context.Background()
	backend, err := Factory(ctx, &logical.BackendConfig{
		Logger:      testLogger(),
		StorageView: newInmemStorage(),
	})
	require.NoError(t, err)
	return backend.(*certAuthBackend), ctx
}

func TestIsValidPrincipalClaim(t *testing.T) {
	tests := []struct {
		claim string
		valid bool
	}{
		{"cn", true},
		{"dns_san", true},
		{"email_san", true},
		{"uri_san", true},
		{"serial", true},
		{"invalid", false},
		{"CN", false},
		{"", false},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.valid, isValidPrincipalClaim(tc.claim), "claim=%q", tc.claim)
	}
}

// =============================================================================
// SensitiveConfigFields Tests
// =============================================================================

func TestParsePEMCertificates(t *testing.T) {
	_, _, caPEM := testCA(t)

	count := parsePEMCertificates(caPEM)
	assert.Equal(t, 1, count)

	count = parsePEMCertificates("not a PEM")
	assert.Equal(t, 0, count)

	count = parsePEMCertificates("")
	assert.Equal(t, 0, count)
}

// =============================================================================
// buildCAPool Tests
// =============================================================================

func TestBuildCAPool(t *testing.T) {
	_, _, caPEM := testCA(t)

	pool, err := buildCAPool(caPEM)
	require.NoError(t, err)
	require.NotNil(t, pool)

	_, err = buildCAPool("not a PEM")
	assert.Error(t, err)
}

// =============================================================================
// principalClaimAllowedValues Tests
// =============================================================================

func TestPrincipalClaimAllowedValues(t *testing.T) {
	values := principalClaimAllowedValues()
	assert.Len(t, values, len(validPrincipalClaims))
	for i, v := range validPrincipalClaims {
		assert.Equal(t, v, values[i])
	}
}

// =============================================================================
// extractPrincipal with empty fields
// =============================================================================

func TestExtractPrincipal_EmptyDNSSAN(t *testing.T) {
	cert := &x509.Certificate{
		DNSNames: []string{},
	}
	assert.Equal(t, "", extractPrincipal(cert, "dns_san"))
}

func TestExtractPrincipal_EmptyEmailSAN(t *testing.T) {
	cert := &x509.Certificate{
		EmailAddresses: []string{},
	}
	assert.Equal(t, "", extractPrincipal(cert, "email_san"))
}

func TestExtractPrincipal_EmptyURISAN(t *testing.T) {
	cert := &x509.Certificate{
		URIs: []*url.URL{},
	}
	assert.Equal(t, "", extractPrincipal(cert, "uri_san"))
}

// =============================================================================
// extractClientCert with nil request
// =============================================================================

func TestExtractClientCert_NilHTTPRequest(t *testing.T) {
	req := &logical.Request{HTTPRequest: nil}
	assert.Nil(t, extractClientCert(req))
}

// =============================================================================
// Full handleLogin flow tests
// =============================================================================
