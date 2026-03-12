package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRevocationChecker_CheckCRL_NotRevoked(t *testing.T) {
	caCert, caKey, _ := testCA(t)
	clientCert := testClientCert(t, caCert, caKey, "good-client")

	// Create an empty CRL (no revoked certs)
	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(1 * time.Hour),
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, caKey)
	if err != nil {
		t.Fatalf("failed to create CRL: %v", err)
	}

	// Serve CRL via HTTP
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-crl")
		w.Write(crlDER)
	}))
	defer srv.Close()

	// Create cert with CRL distribution point
	clientCert.CRLDistributionPoints = []string{srv.URL}

	rc := newRevocationChecker(time.Hour, 5*time.Second)
	err = rc.checkCRL(clientCert, caCert)
	if err != nil {
		t.Fatalf("expected no error for non-revoked cert, got: %v", err)
	}
}

func TestRevocationChecker_CheckCRL_Revoked(t *testing.T) {
	caCert, caKey, _ := testCA(t)
	clientCert := testClientCert(t, caCert, caKey, "revoked-client")

	// Create a CRL listing the client cert as revoked
	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(1 * time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{
				SerialNumber:   clientCert.SerialNumber,
				RevocationTime: time.Now().Add(-10 * time.Minute),
			},
		},
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, caKey)
	if err != nil {
		t.Fatalf("failed to create CRL: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-crl")
		w.Write(crlDER)
	}))
	defer srv.Close()

	clientCert.CRLDistributionPoints = []string{srv.URL}

	rc := newRevocationChecker(time.Hour, 5*time.Second)
	err = rc.checkCRL(clientCert, caCert)
	if !isRevoked(err) {
		t.Fatalf("expected revoked error, got: %v", err)
	}
}

func TestRevocationChecker_CheckCRL_NoCRLDistributionPoints(t *testing.T) {
	caCert, caKey, _ := testCA(t)
	clientCert := testClientCert(t, caCert, caKey, "no-cdp-client")
	// No CRL distribution points set

	rc := newRevocationChecker(time.Hour, 5*time.Second)
	err := rc.checkCRL(clientCert, caCert)
	if err == nil {
		t.Fatal("expected error for cert with no CRL distribution points")
	}
}

func TestRevocationChecker_CheckCRL_CachesResults(t *testing.T) {
	caCert, caKey, _ := testCA(t)
	clientCert := testClientCert(t, caCert, caKey, "cache-test-client")

	requestCount := 0
	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(1 * time.Hour),
	}
	crlDER, _ := x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, caKey)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Write(crlDER)
	}))
	defer srv.Close()

	clientCert.CRLDistributionPoints = []string{srv.URL}

	rc := newRevocationChecker(time.Hour, 5*time.Second)

	// First request fetches
	_ = rc.checkCRL(clientCert, caCert)
	if requestCount != 1 {
		t.Fatalf("expected 1 request, got %d", requestCount)
	}

	// Second request uses cache
	_ = rc.checkCRL(clientCert, caCert)
	if requestCount != 1 {
		t.Fatalf("expected 1 request (cached), got %d", requestCount)
	}
}

func TestRevocationChecker_CheckRevocation_BestEffort(t *testing.T) {
	caCert, caKey, _ := testCA(t)
	clientCert := testClientCert(t, caCert, caKey, "best-effort-client")
	// No CRL or OCSP endpoints — both checks will be inconclusive

	chains := [][]*x509.Certificate{{clientCert, caCert}}
	rc := newRevocationChecker(time.Hour, 5*time.Second)

	// best_effort mode should allow the cert through
	err := rc.checkRevocation(clientCert, chains, "best_effort")
	if err != nil {
		t.Fatalf("expected no error in best_effort mode, got: %v", err)
	}

	// strict modes should reject
	err = rc.checkRevocation(clientCert, chains, "crl")
	if err == nil {
		t.Fatal("expected error in strict crl mode with no endpoints")
	}
}

func TestRevocationChecker_CheckOCSP_NoServers(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	cert := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test"},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	parsedCert, _ := x509.ParseCertificate(certDER)

	rc := newRevocationChecker(time.Hour, 5*time.Second)
	err := rc.checkOCSP(parsedCert, nil)
	if err == nil {
		t.Fatal("expected error when no OCSP servers configured")
	}
}

func TestRevocationChecker_CheckCRL_NilIssuerFails(t *testing.T) {
	caCert, caKey, _ := testCA(t)
	clientCert := testClientCert(t, caCert, caKey, "nil-issuer-client")

	// Create a valid CRL signed by the CA
	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(1 * time.Hour),
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, caKey)
	if err != nil {
		t.Fatalf("failed to create CRL: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(crlDER)
	}))
	defer srv.Close()

	clientCert.CRLDistributionPoints = []string{srv.URL}

	rc := newRevocationChecker(time.Hour, 5*time.Second)

	// With nil issuer, fetchCRL must fail-closed (cannot verify signature)
	err = rc.checkCRL(clientCert, nil)
	if err == nil {
		t.Fatal("expected error when issuer is nil, got nil")
	}
}

func TestRevocationChecker_IsRevoked_WrappedError(t *testing.T) {
	// Direct sentinel
	if !isRevoked(errRevoked) {
		t.Fatal("isRevoked should detect direct errRevoked")
	}

	// Wrapped sentinel
	wrapped := fmt.Errorf("outer: %w", errRevoked)
	if !isRevoked(wrapped) {
		t.Fatal("isRevoked should detect wrapped errRevoked")
	}

	// Unrelated error
	if isRevoked(fmt.Errorf("some other error")) {
		t.Fatal("isRevoked should not match unrelated errors")
	}
}

func TestRevocationChecker_CRLTimeout_SeparateFromOCSP(t *testing.T) {
	rc := newRevocationChecker(time.Hour, 5*time.Second)

	// CRL timeout should be longer than OCSP timeout
	if rc.crlTimeout <= rc.ocspTimeout {
		t.Fatalf("crlTimeout (%v) should be greater than ocspTimeout (%v)", rc.crlTimeout, rc.ocspTimeout)
	}

	// Default: 3 * ocspTimeout = 15s
	if rc.crlTimeout != 15*time.Second {
		t.Fatalf("expected crlTimeout = 15s, got %v", rc.crlTimeout)
	}

	// With very short OCSP timeout, CRL timeout should floor at 15s
	rc2 := newRevocationChecker(time.Hour, 1*time.Second)
	if rc2.crlTimeout < 15*time.Second {
		t.Fatalf("expected crlTimeout >= 15s for short OCSP timeout, got %v", rc2.crlTimeout)
	}
}

func TestIsValidRevocationMode(t *testing.T) {
	tests := []struct {
		mode  string
		valid bool
	}{
		{"", true},
		{"none", true},
		{"crl", true},
		{"ocsp", true},
		{"best_effort", true},
		{"invalid", false},
		{"NONE", false},
	}

	for _, tc := range tests {
		if isValidRevocationMode(tc.mode) != tc.valid {
			t.Fatalf("isValidRevocationMode(%q) = %v, want %v", tc.mode, !tc.valid, tc.valid)
		}
	}
}
