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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
