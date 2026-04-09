package drivers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net/http"
	"testing"
	"time"
)

// generateTestCA creates a self-signed CA certificate and returns the
// base64-encoded PEM data suitable for use as ca_data config values.
func generateTestCA(t *testing.T) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
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
		t.Fatalf("failed to create certificate: %v", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return base64.StdEncoding.EncodeToString(pemBytes)
}

func TestBuildHTTPClient_NoTLSConfig(t *testing.T) {
	config := map[string]string{}
	client, err := BuildHTTPClient(config, 30*time.Second)
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
	config := map[string]string{"tls_skip_verify": "true"}
	client, err := BuildHTTPClient(config, 15*time.Second)
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

func TestBuildHTTPClient_ValidCAData(t *testing.T) {
	caData := generateTestCA(t)
	config := map[string]string{"ca_data": caData}
	client, err := BuildHTTPClient(config, 30*time.Second)
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

func TestBuildHTTPClient_InvalidBase64(t *testing.T) {
	config := map[string]string{"ca_data": "not-valid-base64!!!"}
	_, err := BuildHTTPClient(config, 30*time.Second)
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestBuildHTTPClient_InvalidPEM(t *testing.T) {
	config := map[string]string{
		"ca_data": base64.StdEncoding.EncodeToString([]byte("not a PEM certificate")),
	}
	_, err := BuildHTTPClient(config, 30*time.Second)
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestBuildHTTPClient_BothOptions(t *testing.T) {
	caData := generateTestCA(t)
	config := map[string]string{
		"ca_data":         caData,
		"tls_skip_verify": "true",
	}
	client, err := BuildHTTPClient(config, 30*time.Second)
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
	config := map[string]string{"tls_skip_verify": "true"}
	client, err := BuildHTTPClient(config, 30*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	transport := client.Transport.(*http.Transport)
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("expected MinVersion TLS 1.2, got %d", transport.TLSClientConfig.MinVersion)
	}
}

func TestValidateCAData(t *testing.T) {
	validCA := generateTestCA(t)
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"empty string", "", false},
		{"valid CA", validCA, false},
		{"invalid base64", "not-valid!!!", true},
		{"invalid PEM", base64.StdEncoding.EncodeToString([]byte("not PEM")), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCAData(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCAData() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
