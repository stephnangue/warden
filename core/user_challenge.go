package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/sdk/githttp"
)

// attachUserChallenge adds an RFC 6750 WWW-Authenticate header to a response
// that failed for want of a usable USER principal, pointing the client at the
// mount's protected resource metadata so it can go acquire one and retry.
//
// This is what turns a dead end into a bootstrap: without the challenge a client
// sees only a 401 and has nowhere to go. It is attached to the response rather
// than rendered at the HTTP layer because only here are the namespace and mount
// in hand, and writeLogicalResponse copies resp.Headers before writing.
//
// invalidToken distinguishes the two cases RFC 6750 separates: a credential was
// presented and rejected (error="invalid_token"), versus none was presented at
// all, where the bare challenge is correct and an error code would be a lie.
//
// A no-op when the mount is not a protected resource or metadata is not
// configured: pointing at a document that will 404 is worse than pointing
// nowhere. A missing or invalid AGENT never reaches here — that is a plain
// 401/403 with nothing for the user leg to fix.
func (c *Core) attachUserChallenge(ctx context.Context, req *logical.Request, resp *logical.Response, invalidToken bool) {
	if resp == nil || req == nil {
		return
	}
	params := make([]string, 0, 2)
	if invalidToken {
		params = append(params, `error="invalid_token"`)
	}
	// Omitted when no document would be served — a mount that is not opted in,
	// or metadata not configured. Naming a URL that 404s is worse than naming
	// none: the client follows it and the bootstrap dies silently. RFC 7235 still
	// requires *a* challenge on a 401, so the bare scheme is emitted regardless.
	if metadataURL := c.prmMetadataURL(ctx, req.MountPoint); metadataURL != "" {
		params = append(params, fmt.Sprintf("resource_metadata=%q", metadataURL))
	}

	challenge := "Bearer"
	if len(params) > 0 {
		challenge += " " + strings.Join(params, ", ")
	}

	// Git speaks Basic, not Bearer. On a smart-HTTP path a bare Bearer challenge
	// is unactionable: the client needs to be told to retry with credentials, and
	// on a protected-resource mount the Basic password slot is where the user
	// credential rides. RFC 9110 permits multiple challenges — libcurl picks a
	// scheme it supports, a metadata-aware client picks the other.
	if isGitSmartHTTP(req) {
		challenge = `Basic realm="warden", ` + challenge
	}

	resp.AddHeader("WWW-Authenticate", challenge)
}

// attachGitBasicChallenge attaches a Basic challenge to a transparent-auth
// failure on a git smart-HTTP path.
//
// Git's opening info/refs carries no Authorization, so the role (Basic
// username) and any user credential (Basic password) are both absent and auth
// fails for want of a role. Where the request passed through instead, the
// upstream issues this challenge; where an out-of-band agent forced
// authentication there is no upstream response to relay, and a bare 401 leaves
// the client nothing to act on. Basic only: the agent is what failed, and the
// user leg has nothing to fix.
func attachGitBasicChallenge(req *logical.Request, resp *logical.Response) {
	if req == nil || resp == nil || !isGitSmartHTTP(req) {
		return
	}
	resp.AddHeader("WWW-Authenticate", `Basic realm="warden"`)
}

// prmMetadataURL renders the absolute URL of a mount's protected resource
// metadata, or "" when none would be served.
//
// Built from the configured external base, never from the request's Host header:
// a client controls Host, and this URL is where it will go to authenticate.
// Deriving it from an attacker-supplied value would let a request point its own
// challenge at an attacker's document.
//
// The URL is confirmed by asking the metadata builder for the very document the
// client would fetch, and returning "" if it would not serve one. Re-deriving
// the conditions here instead would let the two drift: the endpoint also
// requires the mount to exist, to be opted in, and to have a derivable
// authorization server. A challenge naming a URL that 404s is worse than no
// challenge, because the client follows it and the bootstrap dies silently.
func (c *Core) prmMetadataURL(ctx context.Context, mountPoint string) string {
	if mountPoint == "" {
		return ""
	}
	ns, err := namespace.FromContext(ctx)
	if err != nil || ns == nil {
		return ""
	}

	// The suffix must match what the metadata endpoint serves, which is the
	// namespace-qualified API path with no trailing slash.
	suffix := "/v1/" + strings.TrimSuffix(ns.Path+mountPoint, "/")
	body, _, err := c.ProtectedResourceMetadata(ctx, suffix)
	if err != nil {
		return ""
	}

	// The external base comes from the document just built rather than a second
	// config read: its `resource` is that base joined with this same suffix, so
	// deriving it back guarantees the challenge and the document agree even if
	// the configuration changes underneath.
	var doc ProtectedResourceMetadata
	if err := json.Unmarshal(body, &doc); err != nil {
		return ""
	}
	base := strings.TrimSuffix(doc.Resource, suffix)
	if base == doc.Resource {
		// The identifier did not end with the suffix, so the two were built
		// differently and any URL derived here would be a guess.
		return ""
	}
	return base + PRMWellKnownPath + suffix
}

// PRMWellKnownPath is the RFC 9728 well-known prefix. Exported so the HTTP layer
// registers exactly the path this challenge points at — a challenge naming a URL
// nothing serves would break the bootstrap silently.
const PRMWellKnownPath = "/.well-known/oauth-protected-resource"

// isGitSmartHTTP reports whether the request targets a Git smart-HTTP endpoint,
// where the client negotiates with Basic auth rather than Bearer.
//
// IsSmartHTTPPath is documented to take the path after "/gateway" and is a pure
// suffix match, so the gateway segment is checked here too — otherwise any path
// merely ending in ".git/info/refs" would draw a spurious Basic challenge.
func isGitSmartHTTP(req *logical.Request) bool {
	// Matched as a segment, not a substring: "foo/gateway-prod/r.git/info/refs"
	// is not a gateway path. The git suffix always follows "gateway/", so this is
	// strictly tighter without losing any genuine path.
	if !strings.Contains(req.Path, "/gateway/") {
		return false
	}
	return githttp.IsSmartHTTPPath(req.Path)
}

// exchangeInputError assigns the HTTP status for a token-exchange input
// resolution failure.
//
// A missing user principal is a 401: the caller can acquire a user identity and
// retry, which is exactly what the paired WWW-Authenticate challenge tells it to
// do. Everything else reaching here is a malformed or unsupported spec, which
// stays the 400 it has always been.
//
// Both branches are load-bearing. Returning the error un-coded would push the
// non-user failures to 500, since GetErrorCode falls through for a plain error;
// coding them all 400 would mask the 401 and stop discovery before it starts.
func exchangeInputError(err error) error {
	if errors.Is(err, credential.ErrUserRequired) {
		return logical.WrapWithCode(http.StatusUnauthorized, err)
	}
	return logical.ErrBadRequestf("token exchange input resolution failed: %s", err.Error())
}

// accessPathMintError restates a missing-user failure on the access path, where
// it can only ever be an operator misconfiguration.
//
// AccessData is returned solely by non-streaming access backends, and
// captureUserContext runs solely in the streaming branch — so req.User is
// structurally nil on every request here. A spec bound to an access mount that
// requires a user therefore fails permanently, and 401 would be a lie twice
// over: it tells the client to authenticate when it already has, and RFC 7235
// would demand a challenge naming somewhere to go, of which there is none.
//
// 500 is the honest answer: the caller did nothing wrong and can do nothing
// about it. The message names the actual fix so it reaches an operator rather
// than sending a client round an authentication loop.
func accessPathMintError(err error) error {
	if !errors.Is(err, credential.ErrUserRequired) {
		return err
	}
	return logical.ErrInternalf(
		"credential spec requires a user principal, but access-path requests cannot carry one "+
			"(per-request user capture runs only on gateway requests): %s", err.Error())
}

// attachUserRequiredChallenge attaches the challenge only when err is the
// missing-user case. Mint can fail for many reasons — an unreachable upstream, a
// malformed spec — and none of those are fixed by acquiring a user identity, so
// pointing at metadata there would send a client on a pointless OAuth round trip.
func (c *Core) attachUserRequiredChallenge(ctx context.Context, req *logical.Request, resp *logical.Response, err error) {
	if !errors.Is(err, credential.ErrUserRequired) {
		return
	}
	c.attachUserChallenge(ctx, req, resp, false)
}
