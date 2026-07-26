package http

import (
	"net/http"

	"github.com/stephnangue/warden/core"
	"github.com/stephnangue/warden/logger"
)

// OIDC issuer discovery + JWKS live at the origin root (not under /v1/) so an
// upstream STS can fetch them at the spec-standard well-known path. They serve
// only public documents (metadata + public keys); the private signing key never
// leaves the process.
const (
	oidcDiscoveryPath = "/.well-known/openid-configuration"
	oidcJWKSPath      = "/oidc/jwks"
)

// isOIDCIssuerPath reports whether p is one of the unauthenticated issuer
// endpoints, which are exempt from the /v1/ path prefix requirement.
func isOIDCIssuerPath(p string) bool {
	return p == oidcDiscoveryPath || p == oidcJWKSPath
}

// handleOIDCDiscovery serves the OpenID Connect discovery document. Unauthenticated
// (an upstream fetches it with no Warden token). Returns 503 when the issuer is
// disabled or not yet ready, so a verifier gets a clear signal instead of an
// empty document.
func handleOIDCDiscovery(c *core.Core, log *logger.GatedLogger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			respondError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		issuer := c.OIDCIssuer()
		if issuer == nil || !issuer.Ready() {
			respondError(w, http.StatusServiceUnavailable, "oidc issuer not available")
			return
		}
		doc, err := issuer.DiscoveryDocument(issuer.IssuerURL() + oidcJWKSPath)
		if err != nil {
			log.Error("failed to build oidc discovery document", logger.Err(err))
			respondError(w, http.StatusInternalServerError, "failed to build discovery document")
			return
		}
		writeJSONBytes(w, doc, issuer.CacheControl())
	})
}

// handleOIDCJWKS serves the JSON Web Key Set of the issuer's public signing keys
// (active plus retired-but-unexpired). Unauthenticated.
func handleOIDCJWKS(c *core.Core, log *logger.GatedLogger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			respondError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		issuer := c.OIDCIssuer()
		if issuer == nil || !issuer.Ready() {
			respondError(w, http.StatusServiceUnavailable, "oidc issuer not available")
			return
		}
		jwks, err := issuer.JWKS()
		if err != nil {
			log.Error("failed to build oidc jwks", logger.Err(err))
			respondError(w, http.StatusInternalServerError, "failed to build jwks")
			return
		}
		writeJSONBytes(w, jwks, issuer.CacheControl())
	})
}

// writeJSONBytes writes a pre-marshalled JSON body with the issuer's derived
// Cache-Control (from the key-activation delay), so a cached JWKS never outlives
// the window in which a rotated-in key must be fetched.
func writeJSONBytes(w http.ResponseWriter, body []byte, cacheControl string) {
	w.Header().Set("Content-Type", "application/json")
	if cacheControl != "" {
		w.Header().Set("Cache-Control", cacheControl)
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
