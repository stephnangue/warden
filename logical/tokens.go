package logical

import (
	"net/http"
	"strings"

	"github.com/stephnangue/warden/listener"
)

const (
	// HeaderWardenToken carries a native Warden session token for the primary
	// (agent) principal.
	HeaderWardenToken = "X-Warden-Token"

	// HeaderWardenAgentToken carries the agent's credential on a dedicated
	// channel so that Authorization is free for the user principal. It carries
	// what Authorization would have carried for a transparent agent: a JWT or a
	// JWT-SVID, resolved by a transparent login against the mount's
	// auto_auth_path. Service-mesh and bearer-JWT agents use it when talking to
	// a protected-resource mount.
	//
	// An agent holding an opaque Warden session token uses HeaderWardenToken
	// instead — that already frees Authorization for the user (rule 1) and is
	// the only header the explicit-auth path recognises.
	HeaderWardenAgentToken = "X-Warden-Agent-Token"
)

// IsJWT reports whether s has the compact-JWS shape ("eyJ", the base64 of the
// `{"` that opens every JOSE header). It is a shape check, not validation — the
// auth mount verifies the token. The same prefix test is open-coded in several
// places in core; this is the shared spelling for new call sites.
func IsJWT(s string) bool {
	return strings.HasPrefix(s, "eyJ")
}

// StripScheme returns the remainder of an Authorization-style header value after
// a case-insensitive scheme prefix match, verbatim (no TrimSpace). Returns "" if
// the value does not carry that scheme. scheme must include its trailing space.
func StripScheme(headerValue, scheme string) string {
	if len(headerValue) > len(scheme) && strings.EqualFold(headerValue[:len(scheme)], scheme) {
		return headerValue[len(scheme):]
	}
	return ""
}

// StripBearer returns the token in an Authorization-style header value, matching
// the "Bearer " scheme case-insensitively and returning the remainder verbatim
// (no TrimSpace). It is the single source of truth for the Bearer strip, so the
// agent and user legs cannot disagree about where a token starts.
func StripBearer(authHeader string) string {
	return StripScheme(authHeader, "Bearer ")
}

// HasTrustedClientCert reports whether the request carries a client certificate
// that Warden trusts as an identity. It covers both direct mTLS peer certs and
// certs forwarded by a trusted proxy: the API listener's middleware normalizes
// both into the request context and strips the raw forwarding headers on every
// branch, so a forged X-Forwarded-Client-Cert / X-SSL-Client-Cert can never
// reach here. Never read those headers directly.
func HasTrustedClientCert(r *http.Request) bool {
	if r == nil {
		return false
	}
	return listener.ForwardedClientCert(r.Context()) != nil
}

// ExtractTokensDefault is the default two-principal resolution rule, shared by
// the framework backend, the httpproxy SDK and the core's own extractor so the
// three cannot drift.
//
//  1. X-Warden-Token present                  -> agent = it, never a user
//  2. userLeg && X-Warden-Agent-Token present -> agent = it, user = authz
//  3. userLeg && trusted client cert          -> agent = "" (the cert), user = authz
//  4. otherwise                               -> agent = authz, user = ""
//
// Steps 2 and 3 are unreachable when userLeg is false, so a non-opted-in mount
// resolves exactly as it did before the user leg existed: X-Warden-Token, then
// Authorization: Bearer, and never a user.
//
// Step 1 does not open the user leg, on either leg. X-Warden-Token is the
// operator credential — a human, a script, the root token — while gateway
// traffic is the workload surface, where identity arrives as a JWT or a client
// certificate. The CLI makes that split explicit: it moves a JWT off
// X-Warden-Token onto Authorization so transparent auth can resolve it. Keeping
// step 1 out of the user leg leaves exactly two ways to present an agent out of
// band — the dedicated header and mTLS — and makes step 1 behave identically
// whether or not the mount is a protected resource.
//
// Step 2 deliberately precedes step 3: a service-mesh sidecar makes a forwarded
// cert present on nearly every request, so testing the cert first would shadow
// the dedicated agent channel and mis-attribute a mesh workload to the sidecar's
// identity.
func ExtractTokensDefault(r *http.Request, userLeg bool) (agent, user string) {
	if r == nil {
		return "", ""
	}
	authz := StripBearer(r.Header.Get("Authorization"))

	if t := r.Header.Get(HeaderWardenToken); t != "" {
		return t, ""
	}
	if userLeg {
		if t := r.Header.Get(HeaderWardenAgentToken); t != "" {
			return t, authz
		}
		if HasTrustedClientCert(r) {
			return "", authz
		}
	}
	return authz, ""
}

// UserBearer returns the Authorization-borne user credential for a provider
// whose own agent channel already matched. Providers with a custom extractor
// call this instead of reaching for the header directly, so the user leg stays
// consistent with ExtractTokensDefault.
func UserBearer(r *http.Request, userLeg bool) string {
	if !userLeg || r == nil {
		return ""
	}
	return StripBearer(r.Header.Get("Authorization"))
}

// AgentOutOfBand resolves the agent from the two channels that free
// Authorization for the user: the dedicated X-Warden-Agent-Token header, then a
// trusted client certificate. It is only consulted when userLeg is true, so a
// non-opted-in mount never sees either.
//
// ok reports whether one of them matched. agent is "" with ok true when the
// certificate is the agent — the core resolves that from the request context.
// Header before cert is deliberate: see ExtractTokensDefault.
func AgentOutOfBand(r *http.Request, userLeg bool) (agent string, ok bool) {
	if !userLeg || r == nil {
		return "", false
	}
	if t := r.Header.Get(HeaderWardenAgentToken); t != "" {
		return t, true
	}
	if HasTrustedClientCert(r) {
		return "", true
	}
	return "", false
}

// ExtractTokensWithChannels applies the default rule to a provider that has its
// own out-of-band agent channels. headers are request headers tried in order
// before anything else; the first non-empty one is the agent, leaving
// Authorization to the user. When none match, resolution falls through to
// X-Warden-Agent-Token, a trusted client cert, and finally Authorization-as-agent
// exactly as ExtractTokensDefault does.
//
// Pass the provider's headers in its existing precedence order: with userLeg
// false the result must stay byte-identical to the pre-0.20 extractor.
//
// X-Warden-Token is special-cased: it may appear in headers to keep a
// provider's agent precedence intact, but it never opens the user leg. See
// ExtractTokensDefault. A provider's own native channel (X-Vault-Token,
// x-api-key, Api-Key, PRIVATE-TOKEN) does open it — those carry a workload's
// agent credential, not an operator session token.
func ExtractTokensWithChannels(r *http.Request, userLeg bool, headers ...string) (agent, user string) {
	if r == nil {
		return "", ""
	}
	for _, h := range headers {
		if t := r.Header.Get(h); t != "" {
			if h == HeaderWardenToken {
				return t, ""
			}
			return t, UserBearer(r, userLeg)
		}
	}
	if a, ok := AgentOutOfBand(r, userLeg); ok {
		return a, StripBearer(r.Header.Get("Authorization"))
	}
	return StripBearer(r.Header.Get("Authorization")), ""
}
