// Package spiffe is the shared SPIFFE substrate for auth methods that act as a
// SPIFFE relying party. It holds the per-trust-domain bundle store, the
// federation client + refresh loop, the trust-domain management paths, and the
// SVID verification helpers. An auth method embeds a Manager, splices in its
// trust-domain paths, and validates credentials with VerifyX509SVID (X.509-SVID)
// or VerifyJWTSVID (JWT-SVID) against the same store.
package spiffe

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// SPIFFE bundle-endpoint profiles (empty = static, non-federated trust domain).
const (
	bundleProfileWeb    = "https_web"
	bundleProfileSPIFFE = "https_spiffe"
)

// TrustDomain is a configured SPIFFE trust domain together with the authorities
// that are authoritative for it. It is stored as JSON under the
// spiffe/trust-domain/<name> storage prefix.
//
// Exactly one of BundlePEM or BundleJSON carries the trust material:
//   - BundlePEM:  one or more concatenated CERTIFICATE PEM blocks (X.509 only).
//   - BundleJSON: a SPIFFE trust-bundle (JWKS) document; both its X.509 and JWT
//     authorities are retained, so the same bundle can verify X.509-SVIDs and
//     JWT-SVIDs.
//
// A federated trust domain (BundleEndpointProfile set) instead pulls its bundle
// from a remote endpoint; the fetched bundle is stored back into BundleJSON (the
// active bundle), so verification via BuildBundleSet is identical for both kinds.
type TrustDomain struct {
	Name       string `json:"name"`
	BundlePEM  string `json:"bundle_pem,omitempty"`
	BundleJSON string `json:"bundle_json,omitempty"`

	// Federation. Empty BundleEndpointProfile => static trust domain.
	BundleEndpointURL     string `json:"bundle_endpoint_url,omitempty"`
	BundleEndpointProfile string `json:"bundle_endpoint_profile,omitempty"` // https_web | https_spiffe
	EndpointSPIFFEID      string `json:"endpoint_spiffe_id,omitempty"`      // https_spiffe only
	WebPKICAPEM           string `json:"web_pki_ca_pem,omitempty"`          // https_web, optional custom roots

	// Fetched federation state, managed by refresh.
	Sequence        uint64 `json:"sequence,omitempty"`
	LastRefreshUnix int64  `json:"last_refresh_unix,omitempty"`
	LastError       string `json:"last_error,omitempty"`
}

// IsFederated reports whether the trust domain pulls its bundle from an endpoint.
func (d *TrustDomain) IsFederated() bool {
	return d.BundleEndpointProfile != ""
}

// parseTrustDomainBundle parses the configured bundle into a SPIFFE bundle for
// the trust domain. It accepts a PEM bundle (X.509 only) or a SPIFFE-JWKS
// document (X.509 and/or JWT authorities), but not both, and requires the result
// to carry at least one authority of either kind. The identity type a given
// mount actually needs (X.509 vs JWT) is enforced at login: a bundle missing the
// required key type yields a verification failure rather than a config error, so
// a JWT-SVID-only trust domain is a valid configuration.
func parseTrustDomainBundle(td spiffeid.TrustDomain, bundlePEM, bundleJSON string) (*spiffebundle.Bundle, error) {
	switch {
	case bundlePEM != "" && bundleJSON != "":
		return nil, fmt.Errorf("provide either bundle_pem or bundle_json, not both")

	case bundlePEM != "":
		certs, err := parsePEMCertChain([]byte(bundlePEM))
		if err != nil {
			return nil, err
		}
		if len(certs) == 0 {
			return nil, fmt.Errorf("bundle_pem contains no valid certificates")
		}
		return spiffebundle.FromX509Authorities(td, certs), nil

	case bundleJSON != "":
		b, err := spiffebundle.Parse(td, []byte(bundleJSON))
		if err != nil {
			return nil, fmt.Errorf("invalid bundle_json: %w", err)
		}
		if b.Empty() {
			return nil, fmt.Errorf("bundle_json contains no X.509 or JWT authorities")
		}
		return b, nil

	default:
		return nil, fmt.Errorf("a bundle is required (set bundle_pem or bundle_json)")
	}
}

// parsePEMCertChain decodes every CERTIFICATE block in a PEM bundle. Non-certificate
// blocks are skipped; a block that fails to parse is an error.
func parsePEMCertChain(pemData []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := pemData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// rootsFromPEM builds an X.509 root pool from PEM. An empty string yields a nil
// pool, which tells the TLS stack to use the system roots.
func rootsFromPEM(pemData string) (*x509.CertPool, error) {
	if pemData == "" {
		return nil, nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(pemData)) {
		return nil, fmt.Errorf("web_pki_ca_pem contains no valid certificates")
	}
	return pool, nil
}

// BuildBundleSet assembles the verification source from all configured trust
// domains. The returned Set maps each trust domain to its bundle and serves both
// the X.509 and JWT verifiers (a spiffebundle.Set is both an x509bundle.Source
// and a jwtbundle.Source).
func BuildBundleSet(domains []*TrustDomain) (*spiffebundle.Set, error) {
	set := spiffebundle.NewSet()
	for _, d := range domains {
		td, err := spiffeid.TrustDomainFromString(d.Name)
		if err != nil {
			return nil, fmt.Errorf("invalid trust domain %q: %w", d.Name, err)
		}
		// A federated trust domain may have no bundle yet (e.g. https_web before its
		// first successful fetch); skip it — SVIDs for it fail closed until fetched.
		if d.IsFederated() && d.BundlePEM == "" && d.BundleJSON == "" {
			continue
		}
		bundle, err := parseTrustDomainBundle(td, d.BundlePEM, d.BundleJSON)
		if err != nil {
			return nil, fmt.Errorf("trust domain %q: %w", d.Name, err)
		}
		set.Add(bundle)
	}
	return set, nil
}
