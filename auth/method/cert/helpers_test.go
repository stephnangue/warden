package cert

import (
	"crypto/x509"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/url"
	"testing"
)

func TestIsValidPrincipalClaim(t *testing.T) {
	tests := []struct {
		claim string
		valid bool
	}{
		{"cn", true},
		{"dns_san", true},
		{"email_san", true},
		{"uri_san", true},
		{"spiffe_id", true},
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
// CertRole.ParseTokenTTL Tests
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

func TestExtractPrincipal_NoSpiffeURI(t *testing.T) {
	u, _ := url.Parse("https://example.com/not-spiffe")
	cert := &x509.Certificate{
		URIs: []*url.URL{u},
	}
	assert.Equal(t, "", extractPrincipal(cert, "spiffe_id"))
}

// =============================================================================
// handleLogin edge cases
// =============================================================================

func TestMatchesAnyGlob(t *testing.T) {
	assert.True(t, matchesAnyGlob([]string{"a.example.com", "b.example.com"}, []string{"*.example.com"}))
	assert.False(t, matchesAnyGlob([]string{"a.other.com"}, []string{"*.example.com"}))
	assert.False(t, matchesAnyGlob([]string{}, []string{"*"}))
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
