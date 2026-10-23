package spiffe

import (
	"crypto/x509"
	"fmt"

	"github.com/stephnangue/warden/auth/helper"
	"github.com/stephnangue/warden/listener"
	"github.com/stephnangue/warden/logical"
)

// maxActChainDepth bounds the nested "act" claims walked by extractActChain.
const maxActChainDepth = 4

// errSPIFFEAuthFailed is a generic error for all authentication failures to
// avoid leaking which specific check failed.
var errSPIFFEAuthFailed = fmt.Errorf("authentication failed")

// extractClientCert returns the X.509-SVID presented via mTLS or a trusted
// forwarding header, or nil. The forwarding middleware stores it in the request
// context (header X-SSL-Client-Cert / X-Forwarded-Client-Cert, or TLS state).
func extractClientCert(req *logical.Request) *x509.Certificate {
	if req.HTTPRequest == nil {
		return nil
	}
	return listener.ForwardedClientCert(req.HTTPRequest.Context())
}

// extractJWTFromRequest returns the JWT-SVID of an introspect/admit request:
// the Authorization bearer of the request discovery forwards, its scheme
// matched case-insensitively as the gateway matches it, else req.ClientToken.
//
// Login does NOT use this — the implicit-auth dispatcher delivers the JWT-SVID
// as the "jwt" body field, read via d.Get("jwt").
func extractJWTFromRequest(req *logical.Request) string {
	if req.HTTPRequest != nil {
		if token := logical.StripBearer(req.HTTPRequest.Header.Get("Authorization")); token != "" {
			return token
		}
	}
	return req.ClientToken
}

// certFingerprint returns the hex SHA-256 of a certificate's DER bytes. This is
// the ClientToken for an X.509-SVID login; it feeds the identity token's cache
// key.
func certFingerprint(cert *x509.Certificate) string { return helper.CertFingerprint(cert) }

// extractActChain walks the RFC 8693 §4.1 "act" delegation chain in a JWT-SVID's
// claims into a flat verified actor list. Returns nil when no "act" claim is
// present; terminates without erroring on malformed layers. A layer's "iss" is
// kept only when it is a non-empty string, never defaulted to the SVID's own iss.
func extractActChain(claims map[string]interface{}) []logical.ActorRef {
	var actors []logical.ActorRef
	current := claims
	for depth := 0; depth < maxActChainDepth; depth++ {
		raw, ok := current["act"]
		if !ok {
			break
		}
		act, ok := raw.(map[string]interface{})
		if !ok {
			break
		}
		sub, ok := act["sub"].(string)
		if !ok || sub == "" {
			break
		}
		iss, _ := act["iss"].(string)
		actors = append(actors, logical.ActorRef{Subject: sub, Issuer: iss})
		current = act
	}
	return actors
}
