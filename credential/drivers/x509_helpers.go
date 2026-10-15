package drivers

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math"
	"strings"
	"time"
)

// clientCertNotBeforeSkew is how far in the future a certificate's validity may start
// and still be accepted: clocks disagree a little, and a certificate issued moments ago
// by a host running ahead should not be refused for it.
const clientCertNotBeforeSkew = 5 * time.Minute

// minClientCertRSABits is the smallest RSA key a client certificate may carry.
const minClientCertRSABits = 2048

// clientCertificate is an X.509 certificate a driver authenticates with, parsed once
// along with the values derived from it, so no request parses PEM or hashes DER.
//
// It holds the public half only. The private key, when Warden holds one, travels
// separately so this value can be logged, compared and shown without care.
type clientCertificate struct {
	leaf *x509.Certificate
	// x5tS256 is the base64url SHA-256 thumbprint of the DER, the x5t#S256 header
	// that tells the authorization server which registered certificate signed.
	x5tS256 string
	// sha1Hex is the upper-case hex SHA-1 thumbprint, which is how Entra ID lists a
	// certificate (customKeyIdentifier) and how operators find it there.
	sha1Hex string
}

// parseClientCertificate parses exactly one PEM CERTIFICATE block holding an RSA key
// of at least minClientCertRSABits that is valid at now.
//
// A chain is refused rather than its first block taken: the server matches the leaf
// alone, so anything after it would be stored, shown and never used.
func parseClientCertificate(pemData string, now time.Time) (*clientCertificate, error) {
	block, rest := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in certificate")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("certificate PEM block is %q, expected CERTIFICATE", block.Type)
	}
	if strings.TrimSpace(string(rest)) != "" {
		return nil, fmt.Errorf("certificate must hold a single PEM CERTIFICATE block (the leaf the server has registered), not a chain")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	pub, ok := leaf.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("certificate key is %T; an RSA key is required (the assertion is signed PS256)", leaf.PublicKey)
	}
	if pub.N.BitLen() < minClientCertRSABits {
		return nil, fmt.Errorf("certificate RSA key is %d bits; at least %d are required", pub.N.BitLen(), minClientCertRSABits)
	}
	if now.After(leaf.NotAfter) {
		return nil, fmt.Errorf("certificate expired at %s", leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	if leaf.NotBefore.After(now.Add(clientCertNotBeforeSkew)) {
		return nil, fmt.Errorf("certificate is not valid until %s", leaf.NotBefore.UTC().Format(time.RFC3339))
	}

	// SHA-1 here is a name for the certificate, not a security check: it is the
	// thumbprint Entra ID lists, so an operator can find the credential by it.
	s256 := sha256.Sum256(leaf.Raw)
	s1 := sha1.Sum(leaf.Raw)
	return &clientCertificate{
		leaf:    leaf,
		x5tS256: base64.RawURLEncoding.EncodeToString(s256[:]),
		sha1Hex: strings.ToUpper(hex.EncodeToString(s1[:])),
	}, nil
}

// DescribeCertificate summarises a PEM certificate for display: who it names, when it
// is valid, how many days remain and the thumbprints the server lists it under. It
// returns nil when pemData is not a certificate. It does not judge validity — an
// expired certificate is described, with negative days remaining, since that is what
// an operator reading the source needs to see.
func DescribeCertificate(pemData string, now time.Time) map[string]any {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	s256 := sha256.Sum256(leaf.Raw)
	s1 := sha1.Sum(leaf.Raw)
	return map[string]any{
		"subject":    leaf.Subject.String(),
		"not_before": leaf.NotBefore.UTC().Format(time.RFC3339),
		"not_after":  leaf.NotAfter.UTC().Format(time.RFC3339),
		// Floored, so an expired certificate reads negative from its first hour on,
		// and 0 means valid for less than a day.
		"days_remaining":  int(math.Floor(leaf.NotAfter.Sub(now).Hours() / 24)),
		"x5t_s256":        base64.RawURLEncoding.EncodeToString(s256[:]),
		"thumbprint_sha1": strings.ToUpper(hex.EncodeToString(s1[:])),
	}
}

// certificateSHA1Thumbprint is the upper-case hex SHA-1 thumbprint of a PEM
// certificate, or "" when it does not parse. Unlike parseClientCertificate it does not
// care whether the certificate is still valid: it names one, it does not trust it.
func certificateSHA1Thumbprint(pemData string) string {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil || block.Type != "CERTIFICATE" {
		return ""
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return ""
	}
	sum := sha1.Sum(block.Bytes)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// matchesPublicKey reports whether pub is the certificate's key. A mismatch means
// every assertion would be refused as signed by an unregistered key, so it is caught
// here, naming the certificate, rather than as an opaque refusal from the server.
func (c *clientCertificate) matchesPublicKey(pub crypto.PublicKey) error {
	want := c.leaf.PublicKey.(*rsa.PublicKey)
	if got, ok := pub.(*rsa.PublicKey); !ok || !want.Equal(got) {
		return fmt.Errorf("the signing key does not match the certificate (x5t#S256 %s)", c.x5tS256)
	}
	return nil
}

// expiresWithin reports whether the certificate stops being valid within d of now.
func (c *clientCertificate) expiresWithin(now time.Time, d time.Duration) bool {
	return c.leaf.NotAfter.Before(now.Add(d))
}
