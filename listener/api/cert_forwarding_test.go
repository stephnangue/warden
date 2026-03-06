package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stephnangue/warden/listener"
)

// generateTestCert creates a self-signed certificate for testing.
func generateTestCert(t *testing.T, cn string) (certPEM string, cert *x509.Certificate) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-1 * time.Minute),
		NotAfter:     time.Now().Add(1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, _ = x509.ParseCertificate(certDER)
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	return certPEM, cert
}

func TestCertForwardingMiddleware_TrustedProxyWithXSSLClientCert(t *testing.T) {
	certPEM, expectedCert := generateTestCert(t, "test-client")
	encodedPEM := url.QueryEscape(certPEM)

	var extractedCert *x509.Certificate
	handler := certForwardingMiddleware([]string{"127.0.0.1/32"})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			extractedCert = listener.ForwardedClientCert(r.Context())
			w.WriteHeader(http.StatusOK)
		}),
	)

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-SSL-Client-Cert", encodedPEM)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if extractedCert == nil {
		t.Fatal("expected certificate in context, got nil")
	}
	if extractedCert.Subject.CommonName != expectedCert.Subject.CommonName {
		t.Fatalf("expected CN %q, got %q", expectedCert.Subject.CommonName, extractedCert.Subject.CommonName)
	}

	// Header should be stripped
	if req.Header.Get("X-SSL-Client-Cert") != "" {
		t.Fatal("X-SSL-Client-Cert header should have been stripped")
	}
}

func TestCertForwardingMiddleware_TrustedProxyWithXFCC(t *testing.T) {
	certPEM, expectedCert := generateTestCert(t, "xfcc-client")
	encodedPEM := url.QueryEscape(certPEM)
	certHash := fmt.Sprintf("%x", sha256.Sum256(expectedCert.Raw))
	xfcc := "Hash=" + certHash + ";Cert=" + encodedPEM + ";Subject=\"CN=xfcc-client\""

	var extractedCert *x509.Certificate
	handler := certForwardingMiddleware([]string{"10.0.0.0/8"})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			extractedCert = listener.ForwardedClientCert(r.Context())
			w.WriteHeader(http.StatusOK)
		}),
	)

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "10.1.2.3:9999"
	req.Header.Set("X-Forwarded-Client-Cert", xfcc)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if extractedCert == nil {
		t.Fatal("expected certificate in context from XFCC header, got nil")
	}
	if extractedCert.Subject.CommonName != expectedCert.Subject.CommonName {
		t.Fatalf("expected CN %q, got %q", expectedCert.Subject.CommonName, extractedCert.Subject.CommonName)
	}
}

func TestCertForwardingMiddleware_UntrustedProxyStripsHeaders(t *testing.T) {
	certPEM, _ := generateTestCert(t, "spoofed-client")
	encodedPEM := url.QueryEscape(certPEM)

	var extractedCert *x509.Certificate
	handler := certForwardingMiddleware([]string{"10.0.0.0/8"})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			extractedCert = listener.ForwardedClientCert(r.Context())
			w.WriteHeader(http.StatusOK)
		}),
	)

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345" // Not in trusted range
	req.Header.Set("X-SSL-Client-Cert", encodedPEM)
	req.Header.Set("X-Forwarded-Client-Cert", "Hash=abc;Cert="+encodedPEM)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if extractedCert != nil {
		t.Fatal("expected no certificate from untrusted proxy, got one")
	}
	// Headers should be stripped
	if req.Header.Get("X-SSL-Client-Cert") != "" {
		t.Fatal("X-SSL-Client-Cert header should have been stripped from untrusted request")
	}
	if req.Header.Get("X-Forwarded-Client-Cert") != "" {
		t.Fatal("X-Forwarded-Client-Cert header should have been stripped from untrusted request")
	}
}

func TestCertForwardingMiddleware_NoTrustedProxies(t *testing.T) {
	certPEM, _ := generateTestCert(t, "no-proxy-client")

	var extractedCert *x509.Certificate
	handler := certForwardingMiddleware(nil)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			extractedCert = listener.ForwardedClientCert(r.Context())
			w.WriteHeader(http.StatusOK)
		}),
	)

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-SSL-Client-Cert", url.QueryEscape(certPEM))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if extractedCert != nil {
		t.Fatal("expected no cert when no trusted proxies configured")
	}
}

func TestCertForwardingMiddleware_TrustedProxyNoCertHeader(t *testing.T) {
	var extractedCert *x509.Certificate
	handler := certForwardingMiddleware([]string{"127.0.0.1/32"})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			extractedCert = listener.ForwardedClientCert(r.Context())
			w.WriteHeader(http.StatusOK)
		}),
	)

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	// No cert headers set

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if extractedCert != nil {
		t.Fatal("expected no cert when no header present, got one")
	}
}

func TestParseCIDRs(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected int
	}{
		{"single CIDR", []string{"10.0.0.0/8"}, 1},
		{"multiple CIDRs", []string{"10.0.0.0/8", "172.16.0.0/12"}, 2},
		{"bare IP converted to /32", []string{"192.168.1.1"}, 1},
		{"empty", nil, 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := parseCIDRs(tc.input)
			if len(result) != tc.expected {
				t.Fatalf("expected %d networks, got %d", tc.expected, len(result))
			}
		})
	}
}

func TestValidateCIDRs(t *testing.T) {
	tests := []struct {
		name    string
		input   []string
		wantErr bool
	}{
		{"valid CIDR", []string{"10.0.0.0/8"}, false},
		{"valid bare IP", []string{"192.168.1.1"}, false},
		{"valid mixed", []string{"10.0.0.0/8", "127.0.0.1"}, false},
		{"empty", nil, false},
		{"invalid entry", []string{"not-a-cidr"}, true},
		{"mixed valid and invalid", []string{"10.0.0.0/8", "garbage", "127.0.0.1"}, true},
		{"multiple invalid", []string{"foo", "bar"}, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateCIDRs(tc.input)
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}
		})
	}
}

func TestExtractRemoteIP(t *testing.T) {
	tests := []struct {
		name     string
		addr     string
		expected string
	}{
		{"host:port", "127.0.0.1:8080", "127.0.0.1"},
		{"bare IP", "192.168.1.1", "192.168.1.1"},
		{"IPv6 with port", "[::1]:8080", "::1"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ip := extractRemoteIP(tc.addr)
			if ip == nil {
				t.Fatalf("expected IP, got nil for %q", tc.addr)
			}
			if ip.String() != tc.expected {
				t.Fatalf("expected %q, got %q", tc.expected, ip.String())
			}
		})
	}
}

func TestParseXFCCHeader(t *testing.T) {
	certPEM, expectedCert := generateTestCert(t, "xfcc-parse-test")
	encodedPEM := url.QueryEscape(certPEM)
	correctHash := fmt.Sprintf("%x", sha256.Sum256(expectedCert.Raw))

	// Standard format with correct hash
	cert := listener.ParseXFCCHeader("Hash=" + correctHash + ";Cert=" + encodedPEM + ";Subject=\"CN=test\"")
	if cert == nil {
		t.Fatal("expected cert from XFCC header with correct hash")
	}
	if cert.Subject.CommonName != expectedCert.Subject.CommonName {
		t.Fatalf("expected CN %q, got %q", expectedCert.Subject.CommonName, cert.Subject.CommonName)
	}

	// With quoted value and no hash (should pass — hash is optional)
	cert = listener.ParseXFCCHeader("Cert=\"" + encodedPEM + "\"")
	if cert == nil {
		t.Fatal("expected cert from quoted XFCC header without hash")
	}

	// No Cert field
	cert = listener.ParseXFCCHeader("Hash=abc;Subject=\"CN=test\"")
	if cert != nil {
		t.Fatal("expected nil cert when no Cert field in XFCC")
	}

	// Invalid cert data
	cert = listener.ParseXFCCHeader("Cert=not-a-cert")
	if cert != nil {
		t.Fatal("expected nil cert for invalid data")
	}

	// Mismatched hash — cert should be rejected
	cert = listener.ParseXFCCHeader("Hash=0000000000000000000000000000000000000000000000000000000000000000;Cert=" + encodedPEM)
	if cert != nil {
		t.Fatal("expected nil cert when hash does not match certificate")
	}

	// Invalid (non-hex) hash — cert should be rejected
	cert = listener.ParseXFCCHeader("Hash=not-a-valid-hash;Cert=" + encodedPEM)
	if cert != nil {
		t.Fatal("expected nil cert when hash is not valid hex")
	}
}

func TestParseSSLClientCertHeader(t *testing.T) {
	certPEM, expectedCert := generateTestCert(t, "ssl-cert-test")

	cert := listener.ParseSSLClientCertHeader(url.QueryEscape(certPEM))
	if cert == nil {
		t.Fatal("expected cert from X-SSL-Client-Cert header")
	}
	if cert.Subject.CommonName != expectedCert.Subject.CommonName {
		t.Fatalf("expected CN %q, got %q", expectedCert.Subject.CommonName, cert.Subject.CommonName)
	}

	// Invalid URL encoding
	cert = listener.ParseSSLClientCertHeader("%zz-invalid")
	if cert != nil {
		t.Fatal("expected nil for invalid URL encoding")
	}

	// Valid URL encoding but not a cert
	cert = listener.ParseSSLClientCertHeader(url.QueryEscape("not a certificate"))
	if cert != nil {
		t.Fatal("expected nil for non-PEM data")
	}
}
