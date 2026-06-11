package cert

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/federation"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"github.com/stephnangue/warden/auth/helper"
)

// SPIFFE bundle-endpoint profiles (empty = static, non-federated trust domain).
const (
	bundleProfileWeb    = "https_web"
	bundleProfileSPIFFE = "https_spiffe"
)

// fetchTimeout bounds a single bundle-endpoint fetch.
const fetchTimeout = 30 * time.Second

// SPIFFETrustDomain is a configured SPIFFE trust domain together with the X.509
// authorities that are authoritative for it. It is stored as JSON under the
// spiffe/trust-domain/<name> storage prefix.
//
// Exactly one of BundlePEM or BundleJSON carries the trust material:
//   - BundlePEM:  one or more concatenated CERTIFICATE PEM blocks.
//   - BundleJSON: a SPIFFE trust-bundle (JWKS) document. Only its X.509
//     authorities are consumed; JWT authorities are ignored.
//
// A federated trust domain (BundleEndpointProfile set) instead pulls its bundle
// from a remote endpoint; the fetched bundle is stored back into BundleJSON (the
// active bundle), so verification via buildBundleSet is identical for both kinds.
type SPIFFETrustDomain struct {
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
func (d *SPIFFETrustDomain) IsFederated() bool {
	return d.BundleEndpointProfile != ""
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
		// A federated trust domain may have no bundle yet (e.g. https_web before its
		// first successful fetch); skip it — SVIDs for it fail closed until fetched.
		if d.IsFederated() && d.BundlePEM == "" && d.BundleJSON == "" {
			continue
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

// fetchFederatedBundle retrieves a federated trust domain's bundle from its
// endpoint per the configured profile:
//   - https_web:    endpoint TLS validated via Web PKI (custom roots or system).
//   - https_spiffe: endpoint authenticated by its SVID against the trust domain's
//     current authorities (bootstrap, then the last fetched bundle).
func fetchFederatedBundle(ctx context.Context, d *SPIFFETrustDomain) (*spiffebundle.Bundle, error) {
	td, err := spiffeid.TrustDomainFromString(d.Name)
	if err != nil {
		return nil, fmt.Errorf("invalid trust domain %q: %w", d.Name, err)
	}

	var opt federation.FetchOption
	switch d.BundleEndpointProfile {
	case bundleProfileWeb:
		roots, err := rootsFromPEM(d.WebPKICAPEM)
		if err != nil {
			return nil, err
		}
		opt = federation.WithWebPKIRoots(roots) // nil => system roots

	case bundleProfileSPIFFE:
		authorities, err := parseTrustDomainAuthorities(td, d.BundlePEM, d.BundleJSON)
		if err != nil {
			return nil, fmt.Errorf("https_spiffe requires a bundle to authenticate the endpoint: %w", err)
		}
		endpointID, err := spiffeid.FromString(d.EndpointSPIFFEID)
		if err != nil {
			return nil, fmt.Errorf("invalid endpoint_spiffe_id %q: %w", d.EndpointSPIFFEID, err)
		}
		opt = federation.WithSPIFFEAuth(x509bundle.FromX509Authorities(td, authorities), endpointID)

	default:
		return nil, fmt.Errorf("trust domain %q is not federated", d.Name)
	}

	bundle, err := federation.FetchBundle(ctx, td, d.BundleEndpointURL, opt)
	if err != nil {
		return nil, err
	}
	return bundle, nil
}

// refreshFederatedTrustDomain fetches d's bundle, and — when it changed — stores
// it as the active bundle and rebuilds the verification set. It is stale-tolerant:
// on fetch error the last-good bundle is kept and the error recorded. The bool
// reports whether the active bundle changed. Must run on the active node (it writes
// storage); d is mutated and persisted in place.
func (b *certAuthBackend) refreshFederatedTrustDomain(ctx context.Context, d *SPIFFETrustDomain) (bool, error) {
	fetchCtx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()

	bundle, err := fetchFederatedBundle(fetchCtx, d)
	if err != nil {
		// Keep the last-good bundle; record the failure (best-effort persist).
		d.LastError = err.Error()
		_ = b.setTrustDomain(ctx, d)
		return false, err
	}

	// A bundle with no X.509 authorities would erase the trust domain's verification
	// material and break the set rebuild for every domain. Reject it (a remote
	// endpoint controls this input) and keep the last-good bundle.
	if len(bundle.X509Authorities()) == 0 {
		d.LastError = "fetched bundle has no X.509 authorities"
		_ = b.setTrustDomain(ctx, d)
		return false, fmt.Errorf("fetched bundle for %q has no X.509 authorities", d.Name)
	}

	newSeq, hasSeq := bundle.SequenceNumber()
	fetchedBefore := d.LastRefreshUnix != 0
	d.LastRefreshUnix = time.Now().Unix()
	d.LastError = ""

	// De-dup: a prior fetch with the same sequence means no change.
	if fetchedBefore && hasSeq && d.Sequence == newSeq {
		return false, b.setTrustDomain(ctx, d)
	}

	marshaled, err := bundle.Marshal()
	if err != nil {
		return false, fmt.Errorf("failed to marshal fetched bundle: %w", err)
	}

	// The fetched bundle becomes the single active source.
	d.BundleJSON = string(marshaled)
	d.BundlePEM = ""
	if hasSeq {
		d.Sequence = newSeq
	}

	if err := b.setTrustDomain(ctx, d); err != nil {
		return false, err
	}
	if err := b.rebuildBundleSet(ctx); err != nil {
		return false, err
	}
	return true, nil
}
