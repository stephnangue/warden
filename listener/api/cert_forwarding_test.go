package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/middleware"
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
	handler := trustedForwardingMiddleware([]string{"127.0.0.1/32"})(
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
	handler := trustedForwardingMiddleware([]string{"10.0.0.0/8"})(
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
	handler := trustedForwardingMiddleware([]string{"10.0.0.0/8"})(
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
	handler := trustedForwardingMiddleware(nil)(
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
	handler := trustedForwardingMiddleware([]string{"127.0.0.1/32"})(
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

// The client's address is taken from forwarding headers only when the
// connection comes from a trusted proxy, and then from the rightmost
// X-Forwarded-For entry that is not itself a trusted proxy: entries to its
// left are whatever the client sent.
func TestTrustedForwardingMiddleware_ClientIP(t *testing.T) {
	for _, tc := range []struct {
		name    string
		peer    string
		headers map[string][]string
		want    string
	}{
		{"untrusted peer: headers ignored", "192.0.2.10:5000",
			map[string][]string{"X-Real-Ip": {"10.1.1.1"}, "X-Forwarded-For": {"10.1.1.2"}}, "192.0.2.10:5000"},
		{"trusted peer: X-Forwarded-For", "10.0.0.5:5000",
			map[string][]string{"X-Forwarded-For": {"203.0.113.7"}}, "203.0.113.7:5000"},
		{"trusted peer: rightmost untrusted entry, not the client's leftmost", "10.0.0.5:5000",
			map[string][]string{"X-Forwarded-For": {"198.51.100.1, 203.0.113.7, 10.0.0.9"}}, "203.0.113.7:5000"},
		{"trusted peer: every entry trusted, the leftmost", "10.0.0.5:5000",
			map[string][]string{"X-Forwarded-For": {"10.0.0.8, 10.0.0.9"}}, "10.0.0.8:5000"},
		{"trusted peer: several X-Forwarded-For lines", "10.0.0.5:5000",
			map[string][]string{"X-Forwarded-For": {"198.51.100.1", "203.0.113.7"}}, "203.0.113.7:5000"},
		{"trusted peer: X-Forwarded-For wins over X-Real-IP", "10.0.0.5:5000",
			map[string][]string{"X-Real-Ip": {"198.51.100.1"}, "X-Forwarded-For": {"203.0.113.7"}}, "203.0.113.7:5000"},
		{"trusted peer: X-Real-IP without X-Forwarded-For", "10.0.0.5:5000",
			map[string][]string{"X-Real-Ip": {"203.0.113.7"}}, "203.0.113.7:5000"},
		{"trusted peer: nothing valid, the peer", "10.0.0.5:5000",
			map[string][]string{"X-Real-Ip": {"not-an-ip"}}, "10.0.0.5:5000"},
		{"trusted peer: entries with ports", "10.0.0.5:5000",
			map[string][]string{"X-Forwarded-For": {"198.51.100.1, 203.0.113.7:4567"}}, "203.0.113.7:5000"},
		{"trusted peer: bracketed IPv6 with port", "10.0.0.5:5000",
			map[string][]string{"X-Forwarded-For": {"198.51.100.1, [2001:db8::7]:443"}}, "[2001:db8::7]:5000"},
		{"trusted peer: an unreadable entry stops the walk, not skipped", "10.0.0.5:5000",
			map[string][]string{"X-Forwarded-For": {"198.51.100.1, unknown"}}, "10.0.0.5:5000"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got string
			handler := trustedForwardingMiddleware([]string{"10.0.0.0/8"})(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r.RemoteAddr }))
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = tc.peer
			for k, vs := range tc.headers {
				req.Header[k] = vs
			}
			handler.ServeHTTP(httptest.NewRecorder(), req)
			if got != tc.want {
				t.Fatalf("RemoteAddr: got %q, want %q", got, tc.want)
			}
		})
	}
}

// A trusted proxy's id is refused when it is not shaped like one, so a header
// cannot put arbitrary text in the audit log; the cluster's internal id header
// never survives the public listener.
func TestTrustedForwardingMiddleware_RequestIDHygiene(t *testing.T) {
	for _, tc := range []struct {
		name, sent string
		kept       bool
	}{
		{"plausible", "lb-7f3a9c/abc-000042", true},
		{"too long", strings.Repeat("a", 129), false},
		{"spaces and quotes", `a "b" c`, false},
		{"newline", "a\nb", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var id, internal string
			handler := trustedForwardingMiddleware([]string{"10.0.0.0/8"})(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					id = middleware.GetReqID(r.Context())
					internal = r.Header.Get(listener.ForwardedRequestIDHeader)
				}))
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = "10.0.0.5:5000"
			req.Header["X-Request-Id"] = []string{tc.sent}
			req.Header.Set(listener.ForwardedRequestIDHeader, "forged")
			handler.ServeHTTP(httptest.NewRecorder(), req)

			if tc.kept != (id == tc.sent) {
				t.Fatalf("id %q for sent %q, kept=%v", id, tc.sent, tc.kept)
			}
			if id == "" {
				t.Fatal("every request must have an id")
			}
			if internal != "" {
				t.Fatalf("the internal id header must not survive the public listener, got %q", internal)
			}
		})
	}
}

// A request id is taken from X-Request-Id only when a trusted proxy sent it;
// anyone else's request gets a new one. The header is left as sent either way,
// so it still reaches the upstream.
func TestTrustedForwardingMiddleware_RequestID(t *testing.T) {
	for _, tc := range []struct {
		name, peer string
		honoured   bool
	}{
		{"trusted proxy", "10.0.0.5:5000", true},
		{"anyone else", "192.0.2.10:5000", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var id, header string
			handler := trustedForwardingMiddleware([]string{"10.0.0.0/8"})(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					id = middleware.GetReqID(r.Context())
					header = r.Header.Get("X-Request-Id")
				}))
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = tc.peer
			req.Header.Set("X-Request-Id", "sent-id")
			handler.ServeHTTP(httptest.NewRecorder(), req)

			if header != "sent-id" {
				t.Fatalf("the X-Request-Id header must be left as sent, got %q", header)
			}
			if tc.honoured && id != "sent-id" {
				t.Fatalf("a trusted proxy's id must be kept, got %q", id)
			}
			if !tc.honoured && (id == "" || id == "sent-id") {
				t.Fatalf("an untrusted caller must get a new id, got %q", id)
			}
		})
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
		{"IPv4-mapped bare IP", []string{"::ffff:10.0.0.5"}, 1},
		{"empty", nil, 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := parseCIDRs(tc.input)
			if len(result) != tc.expected {
				t.Fatalf("expected %d networks, got %d", tc.expected, len(result))
			}
			// Every bare address must match itself, including the
			// IPv4-mapped form, which once parsed as ::/32.
			for _, in := range tc.input {
				if ip := net.ParseIP(in); ip != nil && !isTrustedProxy(ip, result) {
					t.Fatalf("%s does not match its own network %v", in, result)
				}
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

// --- TLS fallback tests ---

func TestCertForwardingMiddleware_TLSFallback_NoProxies(t *testing.T) {
	_, tlsCert := generateTestCert(t, "direct-tls-client")

	var extractedCert *x509.Certificate
	handler := trustedForwardingMiddleware(nil)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			extractedCert = listener.ForwardedClientCert(r.Context())
			w.WriteHeader(http.StatusOK)
		}),
	)

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{tlsCert},
	}

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if extractedCert == nil {
		t.Fatal("expected cert from TLS fallback, got nil")
	}
	if extractedCert.Subject.CommonName != "direct-tls-client" {
		t.Fatalf("expected CN %q, got %q", "direct-tls-client", extractedCert.Subject.CommonName)
	}
}

func TestCertForwardingMiddleware_TLSFallback_TrustedProxyNoHeaders(t *testing.T) {
	_, tlsCert := generateTestCert(t, "passthrough-client")

	var extractedCert *x509.Certificate
	handler := trustedForwardingMiddleware([]string{"127.0.0.1/32"})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			extractedCert = listener.ForwardedClientCert(r.Context())
			w.WriteHeader(http.StatusOK)
		}),
	)

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	// No cert headers — simulates LB passthrough
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{tlsCert},
	}

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if extractedCert == nil {
		t.Fatal("expected cert from TLS fallback in passthrough scenario, got nil")
	}
	if extractedCert.Subject.CommonName != "passthrough-client" {
		t.Fatalf("expected CN %q, got %q", "passthrough-client", extractedCert.Subject.CommonName)
	}
}

func TestCertForwardingMiddleware_HeaderWinsOverTLS(t *testing.T) {
	headerCertPEM, _ := generateTestCert(t, "header-cert")
	_, tlsCert := generateTestCert(t, "tls-cert")

	var extractedCert *x509.Certificate
	handler := trustedForwardingMiddleware([]string{"127.0.0.1/32"})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			extractedCert = listener.ForwardedClientCert(r.Context())
			w.WriteHeader(http.StatusOK)
		}),
	)

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-SSL-Client-Cert", url.QueryEscape(headerCertPEM))
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{tlsCert},
	}

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if extractedCert == nil {
		t.Fatal("expected cert, got nil")
	}
	if extractedCert.Subject.CommonName != "header-cert" {
		t.Fatalf("expected header cert (CN %q) to win over TLS cert, got CN %q", "header-cert", extractedCert.Subject.CommonName)
	}
}

func TestCertForwardingMiddleware_TLSFallback_UntrustedProxyWithTLS(t *testing.T) {
	_, tlsCert := generateTestCert(t, "untrusted-tls-client")

	var extractedCert *x509.Certificate
	handler := trustedForwardingMiddleware([]string{"10.0.0.0/8"})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			extractedCert = listener.ForwardedClientCert(r.Context())
			w.WriteHeader(http.StatusOK)
		}),
	)

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345" // Not in trusted range
	req.Header.Set("X-SSL-Client-Cert", "spoofed-value")
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{tlsCert},
	}

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Headers should be stripped, but TLS cert should be used
	if extractedCert == nil {
		t.Fatal("expected cert from TLS fallback after header stripping, got nil")
	}
	if extractedCert.Subject.CommonName != "untrusted-tls-client" {
		t.Fatalf("expected CN %q, got %q", "untrusted-tls-client", extractedCert.Subject.CommonName)
	}
}

func TestCertForwardingMiddleware_NoCertAnywhere(t *testing.T) {
	var extractedCert *x509.Certificate
	handler := trustedForwardingMiddleware([]string{"127.0.0.1/32"})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			extractedCert = listener.ForwardedClientCert(r.Context())
			w.WriteHeader(http.StatusOK)
		}),
	)

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	// No headers, no TLS

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if extractedCert != nil {
		t.Fatal("expected nil cert when no headers and no TLS, got one")
	}
}

func TestCertForwardingMiddleware_TLSWithEmptyPeerCerts(t *testing.T) {
	var extractedCert *x509.Certificate
	handler := trustedForwardingMiddleware(nil)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			extractedCert = listener.ForwardedClientCert(r.Context())
			w.WriteHeader(http.StatusOK)
		}),
	)

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{}, // TLS but no client cert
	}

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if extractedCert != nil {
		t.Fatal("expected nil cert when TLS has empty PeerCertificates")
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
