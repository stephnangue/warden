// Package spiffetest provides importable helpers for building X.509 SPIFFE
// SVIDs, CAs, and trust bundles in tests. The leaf certificates satisfy
// go-spiffe's SVID rules (exactly one spiffe:// URI SAN, not a CA), so they can
// be verified by x509svid.Verify and presented/served in real TLS handshakes.
//
// The helpers take a testing.TB so they fail the test on error; they are only
// ever pulled in by _test.go files.
package spiffetest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

func serial(tb testing.TB) *big.Int {
	tb.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		tb.Fatalf("spiffetest: serial: %v", err)
	}
	return n
}

// CA returns a self-signed CA certificate and its key, for signing SVIDs.
func CA(tb testing.TB) (*x509.Certificate, *ecdsa.PrivateKey) {
	tb.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("spiffetest: generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(tb),
		Subject:               pkix.Name{CommonName: "spiffetest CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		tb.Fatalf("spiffetest: create CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatalf("spiffetest: parse CA cert: %v", err)
	}
	return cert, key
}

// LeafCert mints a leaf certificate carrying exactly one spiffe:// URI SAN,
// IsCA=false, signed by ca/caKey. opts may mutate the template (e.g. to add a
// second URI SAN or drop the URI for negative tests). spiffeID may be any URI;
// it is not parsed as a SPIFFE ID here, so negative cases are possible.
func LeafCert(tb testing.TB, ca *x509.Certificate, caKey *ecdsa.PrivateKey, spiffeID string, opts ...func(*x509.Certificate)) (*x509.Certificate, *ecdsa.PrivateKey) {
	tb.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("spiffetest: generate leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(tb),
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	if spiffeID != "" {
		u, err := url.Parse(spiffeID)
		if err != nil {
			tb.Fatalf("spiffetest: parse URI %q: %v", spiffeID, err)
		}
		tmpl.URIs = []*url.URL{u}
	}
	for _, opt := range opts {
		opt(tmpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		tb.Fatalf("spiffetest: create leaf cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatalf("spiffetest: parse leaf cert: %v", err)
	}
	return cert, key
}

// SVID builds an *x509svid.SVID (leaf + key + parsed SPIFFE ID) signed by
// ca/caKey. The SVID carries only the leaf in Certificates; verifiers should
// trust ca (use Bundle / CertPool). spiffeID must be a valid SPIFFE ID.
func SVID(tb testing.TB, ca *x509.Certificate, caKey *ecdsa.PrivateKey, spiffeID string, opts ...func(*x509.Certificate)) *x509svid.SVID {
	tb.Helper()
	leaf, key := LeafCert(tb, ca, caKey, spiffeID, opts...)
	id, err := spiffeid.FromString(spiffeID)
	if err != nil {
		tb.Fatalf("spiffetest: invalid SPIFFE ID %q: %v", spiffeID, err)
	}
	return &x509svid.SVID{
		ID:           id,
		Certificates: []*x509.Certificate{leaf},
		PrivateKey:   crypto.Signer(key),
	}
}

// Bundle builds an x509bundle for trust domain td trusting the given
// authorities (typically a CA cert).
func Bundle(tb testing.TB, td string, authorities ...*x509.Certificate) *x509bundle.Bundle {
	tb.Helper()
	domain, err := spiffeid.TrustDomainFromString(td)
	if err != nil {
		tb.Fatalf("spiffetest: invalid trust domain %q: %v", td, err)
	}
	return x509bundle.FromX509Authorities(domain, authorities)
}

// CertPool returns a cert pool trusting the given certs (e.g. for tls RootCAs).
func CertPool(certs ...*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}
	return pool
}
