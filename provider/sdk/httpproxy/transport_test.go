package httpproxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// assertHTTP2Enabled checks that HTTP/2 survived the TLS customization, whichever
// mechanism the compiling toolchain records it with. From Go 1.27 the http2 helper
// delegates to the standard library's native HTTP/2 and flips Transport.Protocols;
// before that it prepended "h2" to the TLS config's NextProtos. Which one applies is
// decided by the installed toolchain's release tags, not by the module's go
// directive, so asserting either alone makes the test pass or fail by toolchain.
func assertHTTP2Enabled(t *testing.T, transport *http.Transport) {
	t.Helper()

	if transport.Protocols != nil && transport.Protocols.HTTP2() {
		return
	}
	assert.Contains(t, transport.TLSClientConfig.NextProtos, "h2",
		"HTTP/2 enabled through neither Transport.Protocols nor TLSClientConfig.NextProtos")
}

// generateTestCACert creates a self-signed CA certificate for testing and
// returns its PEM-encoded bytes.
func generateTestCACert(t *testing.T) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(1 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}

func TestNewTransportWithTLS_SkipVerifyOnly(t *testing.T) {
	transport, err := NewTransportWithTLS("", true)
	require.NoError(t, err)
	require.NotNil(t, transport)
	assert.True(t, transport.TLSClientConfig.InsecureSkipVerify)
	assert.Nil(t, transport.TLSClientConfig.RootCAs)
}

func TestNewTransportWithTLS_ValidCAData(t *testing.T) {
	caPEM := generateTestCACert(t)
	caB64 := base64.StdEncoding.EncodeToString(caPEM)

	transport, err := NewTransportWithTLS(caB64, false)
	require.NoError(t, err)
	require.NotNil(t, transport)
	assert.False(t, transport.TLSClientConfig.InsecureSkipVerify)
	assert.NotNil(t, transport.TLSClientConfig.RootCAs)
	// Verify HTTP/2 is properly configured after TLS customization
	assertHTTP2Enabled(t, transport)
}

func TestNewTransportWithTLS_InvalidBase64(t *testing.T) {
	_, err := NewTransportWithTLS("!!!not-base64!!!", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not valid base64")
}

func TestNewTransportWithTLS_InvalidPEM(t *testing.T) {
	notPEM := base64.StdEncoding.EncodeToString([]byte("this is not PEM data"))
	_, err := NewTransportWithTLS(notPEM, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no valid PEM certificates")
}

func TestNewTransportWithTLS_BothCAAndSkipVerify(t *testing.T) {
	caPEM := generateTestCACert(t)
	caB64 := base64.StdEncoding.EncodeToString(caPEM)

	transport, err := NewTransportWithTLS(caB64, true)
	require.NoError(t, err)
	require.NotNil(t, transport)
	assert.True(t, transport.TLSClientConfig.InsecureSkipVerify)
	assert.NotNil(t, transport.TLSClientConfig.RootCAs)
}

func TestNewTransportWithTLS_EmptyCANoSkip(t *testing.T) {
	transport, err := NewTransportWithTLS("", false)
	require.NoError(t, err)
	require.NotNil(t, transport)
	assert.False(t, transport.TLSClientConfig.InsecureSkipVerify)
	assert.Nil(t, transport.TLSClientConfig.RootCAs)
}
