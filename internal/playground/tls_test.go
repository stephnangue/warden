package playground

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every name the fixtures are reached by must verify against the pool, or the
// configuration the playground writes would need tls_skip_verify.
func TestTLS_VerifiesForEveryFixtureName(t *testing.T) {
	tl, err := NewTLS()
	require.NoError(t, err)

	for _, name := range []string{"localhost", "127.0.0.1", "::1"} {
		_, err := tl.Certificate.Leaf.Verify(x509.VerifyOptions{
			DNSName:   name,
			Roots:     tl.Pool,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
		assert.NoError(t, err, name)
	}

	_, err = tl.Certificate.Leaf.Verify(x509.VerifyOptions{DNSName: "bank.example", Roots: tl.Pool})
	assert.Error(t, err, "valid for loopback names only")
}

// The PEM and base64 forms the bootstrap hands to Warden are the same
// certificate the fixtures serve.
func TestTLS_Encodings(t *testing.T) {
	tl, err := NewTLS()
	require.NoError(t, err)

	block, _ := pem.Decode([]byte(tl.CAPEM))
	require.NotNil(t, block)
	assert.Equal(t, tl.Certificate.Leaf.Raw, block.Bytes)

	decoded, err := base64.StdEncoding.DecodeString(tl.CAData())
	require.NoError(t, err)
	assert.Equal(t, tl.CAPEM, string(decoded))
}

// A client built from ClientConfig completes a handshake with a server built
// from ServerConfig, and trusts nothing else.
func TestTLS_Handshake(t *testing.T) {
	tl, err := NewTLS()
	require.NoError(t, err)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	srv.TLS = tl.ServerConfig()
	srv.StartTLS()
	t.Cleanup(srv.Close)

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tl.ClientConfig()}}
	resp, err := client.Get(srv.URL)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)

	other := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(other.Close)
	_, err = client.Get(other.URL)
	assert.Error(t, err, "a certificate the playground did not make is refused")
}
