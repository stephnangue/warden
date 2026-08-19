package http

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/stephnangue/warden/core"
	"github.com/stephnangue/warden/logger"
)

// prmPath is the RFC 9728 well-known prefix. The resource's own path is appended
// to it — "path insertion" — so one origin can describe many resources:
//
//	/.well-known/oauth-protected-resource/v1/team-a/github
//
// It lives at the origin root, outside /v1/, because a client fetches it before
// it has any credential and without knowing Warden's API layout.
//
// Taken from core rather than restated: core builds the WWW-Authenticate
// challenge that points here, and a challenge naming a URL this layer does not
// serve would break the bootstrap silently.
const prmPath = core.PRMWellKnownPath

// isPRMPath reports whether p addresses protected-resource metadata: the bare
// prefix or anything beneath it. Unlike the OIDC issuer paths this is a subtree,
// since the resource path is carried in the URL.
func isPRMPath(p string) bool {
	return p == prmPath || strings.HasPrefix(p, prmPath+"/")
}

// handlePRM serves RFC 9728 protected resource metadata.
//
// Unauthenticated by design: a client fetches this precisely because it has no
// user credential yet. Every "no document here" case — feature disabled, unknown
// path, mount not opted in, no derivable authorization server — is a plain 404.
// Distinguishing them would let an unauthenticated caller probe the mount table,
// and none of the distinctions are actionable by a client.
//
// This deliberately differs from the OIDC issuer endpoints, which return 503
// when disabled: there, a verifier that reaches a configured issuer URL benefits
// from knowing the issuer is merely not ready. Here the URL itself is the
// question being asked.
func handlePRM(c *core.Core, log *logger.GatedLogger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// HEAD is allowed alongside GET: net/http serves it from the same
		// handler with the body suppressed, and a client probing for the
		// document's existence should not have to fetch it.
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			// RFC 9110 requires Allow on a 405.
			w.Header().Set("Allow", "GET, HEAD")
			respondError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		// Registered at the origin root, so this handler bypasses the seal check
		// handleLogical performs. It dereferences the namespace store and mount
		// table, neither of which exists while sealed.
		if c == nil || c.Sealed() {
			respondError(w, http.StatusServiceUnavailable, "warden is sealed")
			return
		}

		body, ttl, err := c.ProtectedResourceMetadata(r.Context(), prmSuffix(r.URL.Path))
		if err != nil {
			if !errors.Is(err, core.ErrNotProtectedResource) {
				log.Error("failed to build protected resource metadata",
					logger.Err(err), logger.String("path", r.URL.Path))
			}
			respondError(w, http.StatusNotFound, "no protected resource metadata for this path")
			return
		}

		writeJSONBytes(w, body, prmCacheControl(ttl))
	})
}

// prmSuffix extracts the resource path a request is asking about — everything
// after the well-known prefix. Both the bare prefix and its subtree are routed
// here, so the bare form yields "" and is rejected downstream as naming no
// resource. The suffix is passed through verbatim, including any non-canonical
// segments: the core rejects those rather than normalizing, so the identifier
// published in a document is always the one that was requested.
func prmSuffix(urlPath string) string {
	return strings.TrimPrefix(urlPath, prmPath)
}

// prmCacheControl renders the document lifetime as a Cache-Control value. The
// document is derived from live mount configuration, so this bounds how long a
// client may act on a stale authorization server. The TTL is returned alongside
// the body, from the same config generation, so the header cannot describe a
// different document than the one being served.
func prmCacheControl(ttl time.Duration) string {
	if ttl <= 0 {
		return ""
	}
	return fmt.Sprintf("public, max-age=%d", int(ttl.Seconds()))
}
