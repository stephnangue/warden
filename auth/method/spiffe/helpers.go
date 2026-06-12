package spiffe

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"

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

// extractJWTFromRequest pulls a JWT-SVID off an introspect request, header-first:
//  1. Direct HTTP call — Authorization: Bearer <jwt>.
//  2. In-process call from the system-backend aggregator — the raw JWT in
//     req.ClientToken.
//
// Login does NOT use this — the implicit-auth dispatcher delivers the JWT-SVID
// as the "jwt" body field, read via d.Get("jwt").
func extractJWTFromRequest(req *logical.Request) string {
	if req.HTTPRequest != nil {
		if auth := req.HTTPRequest.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			return strings.TrimPrefix(auth, "Bearer ")
		}
	}
	return req.ClientToken
}

// certFingerprint returns the hex SHA-256 of a certificate's DER bytes. This is
// the ClientToken for an X.509-SVID login; it feeds the spiffe_role cache key.
func certFingerprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(hash[:])
}

// resolveAudience returns the role's bound audiences (the source of truth for
// JWT-SVID validation). Empty means the role does not permit JWT-SVID logins.
func resolveAudience(role *SPIFFERole) []string {
	return role.BoundAudiences
}

// extractActChain walks the RFC 8693 §4.1 "act" delegation chain in a JWT-SVID's
// claims into a flat verified actor list. Returns nil when no "act" claim is
// present; terminates without erroring on malformed layers.
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
		actors = append(actors, logical.ActorRef{Subject: sub, Verified: true})
		current = act
	}
	return actors
}

// extractGroupsClaim extracts a string slice from a JWT-SVID claim. Handles a
// JSON array, a single string, or a comma-separated string.
func extractGroupsClaim(claims map[string]interface{}, claimName string) []string {
	value, ok := claims[claimName]
	if !ok {
		return nil
	}
	switch v := value.(type) {
	case []interface{}:
		groups := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				groups = append(groups, s)
			}
		}
		return groups
	case string:
		if v == "" {
			return nil
		}
		if strings.Contains(v, ",") {
			parts := strings.Split(v, ",")
			groups := make([]string, 0, len(parts))
			for _, p := range parts {
				if s := strings.TrimSpace(p); s != "" {
					groups = append(groups, s)
				}
			}
			return groups
		}
		return []string{v}
	default:
		return nil
	}
}
