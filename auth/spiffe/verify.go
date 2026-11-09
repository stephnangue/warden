package spiffe

import (
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	jwtparse "github.com/stephnangue/warden/helper"
)

// VerifyX509SVIDChain validates that certs (leaf first, optional
// intermediates) form a spec-compliant X.509-SVID, without binding it to any
// trust domain or ID beyond what the set trusts.
//
// It delegates the SVID rules to go-spiffe's x509svid.Verify: exactly one URI
// SAN holding a valid SPIFFE ID, a non-CA leaf without certificate/CRL signing
// usage, and a chain to the X.509 authorities of the SVID's own trust domain in
// set. It returns the verified SPIFFE ID and the verified chains.
func VerifyX509SVIDChain(set *spiffebundle.Set, certs []*x509.Certificate) (spiffeid.ID, [][]*x509.Certificate, error) {
	if set == nil {
		return spiffeid.ID{}, nil, fmt.Errorf("no trust bundles loaded")
	}
	// set is both an x509bundle.Source and a jwtbundle.Source; Verify uses the
	// X.509 authorities for the SVID's trust domain.
	id, chains, err := x509svid.Verify(certs, set)
	if err != nil {
		return spiffeid.ID{}, nil, err
	}
	return id, chains, nil
}

// VerifyJWTSVIDToken validates a JWT-SVID, without binding it to any trust
// domain or ID beyond what the set trusts.
//
// It delegates the SVID rules to go-spiffe's jwtsvid.ParseAndValidate: a 'sub'
// holding a valid SPIFFE ID, a signature from the JWT authorities of the SVID's
// own trust domain in set, an unexpired 'exp', and an 'aud' that intersects
// audience (the JWT-SVID audience requirement). audience must be non-empty; an
// empty audience would disable the mandatory audience check.
func VerifyJWTSVIDToken(set *spiffebundle.Set, token string, audience []string) (*jwtsvid.SVID, error) {
	if set == nil {
		return nil, fmt.Errorf("no trust bundles loaded")
	}
	if len(audience) == 0 {
		return nil, fmt.Errorf("an audience is required to validate a JWT-SVID")
	}
	return jwtsvid.ParseAndValidate(token, set, audience)
}

// IsJWTSVID reports whether token is a JWT whose unverified subject is a
// SPIFFE ID: the bearer that is taken as a JWT-SVID, in preference to a
// forwarded certificate (a mesh sidecar forwards one on most requests, which
// must not shadow an explicitly presented JWT-SVID). The signature is not
// checked here; VerifyJWTSVIDToken checks it.
func IsJWTSVID(token string) bool {
	if !strings.HasPrefix(token, "eyJ") {
		return false
	}
	claims, err := jwtparse.ParseJWTClaimsUnverified(token)
	if err != nil {
		return false
	}
	sub, _ := claims["sub"].(string)
	return strings.HasPrefix(sub, "spiffe://")
}
