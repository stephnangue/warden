package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckPlaygroundFlags(t *testing.T) {
	tests := []struct {
		name    string
		flags   playgroundFlags
		wantErr string
	}{
		{name: "plain playground", flags: playgroundFlags{playground: true}},
		{name: "fixture addresses with the playground", flags: playgroundFlags{playground: true, addrSet: true}},
		{name: "fixture addresses alone", flags: playgroundFlags{addrSet: true}, wantErr: "can only be used with -dev-playground"},
		{name: "spiffe", flags: playgroundFlags{playground: true, spiffe: true}, wantErr: "-dev-tls-spiffe"},
		{name: "required client cert with a CA", flags: playgroundFlags{playground: true, requireClientCert: true, clientCAFile: "ca.pem"}, wantErr: "-dev-tls-require-client-cert"},
		{name: "required client cert without a CA has no effect", flags: playgroundFlags{playground: true, requireClientCert: true}},
		{name: "a client CA alone only asks for a certificate", flags: playgroundFlags{playground: true, clientCAFile: "ca.pem"}},
		{name: "spiffe without the playground is not ours to refuse", flags: playgroundFlags{spiffe: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkPlaygroundFlags(tt.flags)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			assert.NoError(t, err)
		})
	}
}

// testCert issues a certificate for 127.0.0.1 and localhost, signed by parent
// (self-signed when parent is nil).
func testCert(t *testing.T, isCA bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "test"},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// The authorization server trusts the dev certificate file alone, so the file
// must verify the listener on its own.
func TestCheckPlaygroundTrust(t *testing.T) {
	_, _, selfSigned := testCert(t, true, nil, nil)
	ca, caKey, caPEM := testCert(t, true, nil, nil)
	_, _, leafPEM := testCert(t, false, ca, caKey)

	assert.NoError(t, checkPlaygroundTrust(selfSigned, "https://127.0.0.1:8400"), "the auto-generated shape")
	assert.NoError(t, checkPlaygroundTrust(selfSigned, "https://localhost:8400"))
	assert.NoError(t, checkPlaygroundTrust(leafPEM+caPEM, "https://127.0.0.1:8400"), "a leaf with its CA appended")
	assert.NoError(t, checkPlaygroundTrust(leafPEM, "https://127.0.0.1:8400"), "a leaf in the pool is pinned, CA or not")

	err := checkPlaygroundTrust(selfSigned, "https://10.1.2.3:8400")
	require.Error(t, err, "a name the certificate does not cover")
	assert.Contains(t, err.Error(), "does not verify the dev listener at 10.1.2.3")
	assert.ErrorContains(t, checkPlaygroundTrust("not a pem", "https://127.0.0.1:8400"), "holds no certificate")
}
