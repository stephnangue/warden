package httputil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"testing"
	"time"
)

// generateTestCAPEM returns a self-signed CA certificate as raw PEM bytes.
func generateTestCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Test CA"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}

func TestBuildHTTPClient_NoTLSConfig(t *testing.T) {
	client, err := BuildHTTPClient(nil, false, 30*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client.Timeout != 30*time.Second {
		t.Errorf("expected timeout 30s, got %v", client.Timeout)
	}
	if client.Transport != nil {
		t.Error("expected nil transport when no TLS config set")
	}
}

func TestBuildHTTPClient_TLSSkipVerify(t *testing.T) {
	client, err := BuildHTTPClient(nil, true, 15*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected *http.Transport")
	}
	if !transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify to be true")
	}
}

func TestBuildHTTPClient_ValidCAPEM(t *testing.T) {
	caPEM := generateTestCAPEM(t)
	client, err := BuildHTTPClient(caPEM, false, 30*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected *http.Transport")
	}
	if transport.TLSClientConfig.RootCAs == nil {
		t.Error("expected RootCAs to be set")
	}
	if transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify to be false")
	}
}

func TestBuildHTTPClient_InvalidPEM(t *testing.T) {
	_, err := BuildHTTPClient([]byte("not a PEM certificate"), false, 30*time.Second)
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestBuildHTTPClient_BothOptions(t *testing.T) {
	caPEM := generateTestCAPEM(t)
	client, err := BuildHTTPClient(caPEM, true, 30*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected *http.Transport")
	}
	if !transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify to be true")
	}
	if transport.TLSClientConfig.RootCAs == nil {
		t.Error("expected RootCAs to be set")
	}
}

func TestBuildHTTPClient_MinTLSVersion(t *testing.T) {
	client, err := BuildHTTPClient(nil, true, 30*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	transport := client.Transport.(*http.Transport)
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("expected MinVersion TLS 1.2, got %d", transport.TLSClientConfig.MinVersion)
	}
}
