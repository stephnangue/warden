package cert

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"github.com/stephnangue/warden/auth/helper"
)

// SPIFFETrustDomain is a configured SPIFFE trust domain together with the X.509
// authorities that are authoritative for it. It is stored as JSON under the
// spiffe/trust-domain/<name> storage prefix.
//
// Exactly one of BundlePEM or BundleJSON carries the trust material:
//   - BundlePEM:  one or more concatenated CERTIFICATE PEM blocks.
//   - BundleJSON: a SPIFFE trust-bundle (JWKS) document. Only its X.509
//     authorities are consumed; JWT authorities are ignored.
//
// The struct is intentionally minimal but kept extensible: federation (remote
// bundle endpoints and periodic refresh) will add fields here in a later change.
type SPIFFETrustDomain struct {
	Name       string `json:"name"`
	BundlePEM  string `json:"bundle_pem,omitempty"`
	BundleJSON string `json:"bundle_json,omitempty"`
}

// parseTrustDomainAuthorities parses the configured bundle into the X.509
// authorities for the trust domain. It accepts a PEM bundle or a SPIFFE-JWKS
// document, but not both, and requires at least one X.509 authority.
func parseTrustDomainAuthorities(td spiffeid.TrustDomain, bundlePEM, bundleJSON string) ([]*x509.Certificate, error) {
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
		return certs, nil

	case bundleJSON != "":
		// spiffebundle parses the JWKS form and exposes only its X.509 authorities.
		b, err := spiffebundle.Parse(td, []byte(bundleJSON))
		if err != nil {
			return nil, fmt.Errorf("invalid bundle_json: %w", err)
		}
		authorities := b.X509Authorities()
		if len(authorities) == 0 {
			return nil, fmt.Errorf("bundle_json contains no X.509 authorities")
		}
		return authorities, nil

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

// buildBundleSet assembles the X.509 verification source from all configured
// trust domains. The returned Set maps each trust domain to its authorities and
// is the source consumed by verifySPIFFE.
func buildBundleSet(domains []*SPIFFETrustDomain) (*x509bundle.Set, error) {
	bundles := make([]*x509bundle.Bundle, 0, len(domains))
	for _, d := range domains {
		td, err := spiffeid.TrustDomainFromString(d.Name)
		if err != nil {
			return nil, fmt.Errorf("invalid trust domain %q: %w", d.Name, err)
		}
		authorities, err := parseTrustDomainAuthorities(td, d.BundlePEM, d.BundleJSON)
		if err != nil {
			return nil, fmt.Errorf("trust domain %q: %w", d.Name, err)
		}
		bundles = append(bundles, x509bundle.FromX509Authorities(td, authorities))
	}
	return x509bundle.NewSet(bundles...), nil
}

// verifySPIFFE validates that certs (leaf first, optional intermediates) form a
// spec-compliant X.509-SVID and binds it to a role's trust domain.
//
// It delegates the SVID rules to go-spiffe's x509svid.Verify — exactly one URI
// SAN holding a valid SPIFFE ID, a non-CA leaf without certificate/CRL signing
// usage, and a chain to the X.509 authorities of the SVID's own trust domain in
// set — then additionally requires the SVID's trust domain to equal expectedTD
// and, when allowedIDs is non-empty, its SPIFFE ID to match one of the patterns.
// It returns the verified SPIFFE ID and the verified chains.
func verifySPIFFE(set *x509bundle.Set, certs []*x509.Certificate, expectedTD spiffeid.TrustDomain, allowedIDs []string) (spiffeid.ID, [][]*x509.Certificate, error) {
	id, chains, err := x509svid.Verify(certs, set)
	if err != nil {
		return spiffeid.ID{}, nil, err
	}
	if !id.MemberOf(expectedTD) {
		return spiffeid.ID{}, nil, fmt.Errorf("SVID trust domain %q does not match role trust domain %q", id.TrustDomain().Name(), expectedTD.Name())
	}
	if len(allowedIDs) > 0 && !helper.MatchAny(id.String(), allowedIDs) {
		return spiffeid.ID{}, nil, fmt.Errorf("SPIFFE ID %q not allowed by role", id.String())
	}
	return id, chains, nil
}
