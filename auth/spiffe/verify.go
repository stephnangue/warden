package spiffe

import (
	"crypto/x509"
	"fmt"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"github.com/stephnangue/warden/auth/helper"
)

// VerifyX509SVID validates that certs (leaf first, optional intermediates) form a
// spec-compliant X.509-SVID and binds it to a role's trust domain.
//
// It delegates the SVID rules to go-spiffe's x509svid.Verify — exactly one URI
// SAN holding a valid SPIFFE ID, a non-CA leaf without certificate/CRL signing
// usage, and a chain to the X.509 authorities of the SVID's own trust domain in
// set — then additionally requires the SVID's trust domain to equal expectedTD
// and, when allowedIDs is non-empty, its SPIFFE ID to match one of the patterns.
// It returns the verified SPIFFE ID and the verified chains.
func VerifyX509SVID(set *spiffebundle.Set, certs []*x509.Certificate, expectedTD spiffeid.TrustDomain, allowedIDs []string) (spiffeid.ID, [][]*x509.Certificate, error) {
	if set == nil {
		return spiffeid.ID{}, nil, fmt.Errorf("no trust bundles loaded")
	}
	// set is both an x509bundle.Source and a jwtbundle.Source; Verify uses the
	// X.509 authorities for the SVID's trust domain.
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

// VerifyJWTSVID validates a JWT-SVID and binds it to a role's trust domain.
//
// It delegates the SVID rules to go-spiffe's jwtsvid.ParseAndValidate — a 'sub'
// holding a valid SPIFFE ID, a signature from the JWT authorities of the SVID's
// own trust domain in set, an unexpired 'exp', and an 'aud' that intersects
// audience (the JWT-SVID audience requirement) — then additionally requires the
// SVID's trust domain to equal expectedTD and, when allowedIDs is non-empty, its
// SPIFFE ID to match one of the patterns. audience must be non-empty; an empty
// audience would disable the mandatory audience check. It returns the verified
// JWT-SVID (its ID is the principal, its Claims carry any group/metadata claims).
func VerifyJWTSVID(set *spiffebundle.Set, token string, audience []string, expectedTD spiffeid.TrustDomain, allowedIDs []string) (*jwtsvid.SVID, error) {
	if set == nil {
		return nil, fmt.Errorf("no trust bundles loaded")
	}
	if len(audience) == 0 {
		return nil, fmt.Errorf("an audience is required to validate a JWT-SVID")
	}
	svid, err := jwtsvid.ParseAndValidate(token, set, audience)
	if err != nil {
		return nil, err
	}
	if !svid.ID.MemberOf(expectedTD) {
		return nil, fmt.Errorf("SVID trust domain %q does not match role trust domain %q", svid.ID.TrustDomain().Name(), expectedTD.Name())
	}
	if len(allowedIDs) > 0 && !helper.MatchAny(svid.ID.String(), allowedIDs) {
		return nil, fmt.Errorf("SPIFFE ID %q not allowed by role", svid.ID.String())
	}
	return svid, nil
}
