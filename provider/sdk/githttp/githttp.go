// Package githttp is the shared scaffolding for httpproxy providers that
// carry both REST and Git smart-HTTP traffic on the same mount. It packages
// the parts that are identical across git hosts — path-suffix detection,
// body-size constants, Basic Auth credential formatting, role extraction
// from the Basic Auth username, and the unauthenticated-probe gate — and
// exposes them through a single BuildHooks(Options) constructor that
// returns the three httpproxy.ProviderSpec hooks a git-aware provider must
// wire (ResolveUpstream, GetAuthRoleFromRequest, IsUnauthenticatedRequest).
//
// Each consumer supplies host-specific knobs via Options: the Basic Auth
// username (GitHub uses "x-access-token", GitLab uses "oauth2"), the
// credential type and token field name, and a closure that derives the
// git host URL from the configured REST URL. Everything else is provided
// by the SDK.
package githttp

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/sdk/httpproxy"
)

// DefaultMaxBodySize is the default cap on Git request bodies (2 GiB).
// Big enough for most pushes; operators with larger repos bump it via the
// git_max_body_size config field.
const DefaultMaxBodySize int64 = 2 * 1024 * 1024 * 1024

// MinMaxBodySize is the lower bound for git_max_body_size validation.
// Below this, Git clones of even trivial repos start failing.
const MinMaxBodySize int64 = 1 * 1024 * 1024 // 1 MiB

// MaxMaxBodySize is the upper bound for git_max_body_size validation.
// Repos larger than this should be using LFS-aware infrastructure rather
// than the gateway.
const MaxMaxBodySize int64 = 10 * 1024 * 1024 * 1024 // 10 GiB

// smartHTTPSuffixes are the smart-HTTP endpoint suffixes that identify a
// Git-protocol request inside the gateway path. Unexported because the
// slice is mutable and consumers should call IsSmartHTTPPath instead of
// reading the list directly.
var smartHTTPSuffixes = []string{
	".git/info/refs",
	".git/git-upload-pack",
	".git/git-receive-pack",
}

// IsSmartHTTPPath reports whether apiPath (the portion of the URL after
// "/gateway") is a Git smart-HTTP endpoint.
func IsSmartHTTPPath(apiPath string) bool {
	for _, suffix := range smartHTTPSuffixes {
		if strings.HasSuffix(apiPath, suffix) {
			return true
		}
	}
	return false
}

// pathAfterGateway extracts the API-shaped path slice from a routed gateway
// request URL. Wraps the httpproxy helper with a fall-back to the input
// when no "/gateway" segment is present (defensive — routed gateway
// requests always contain one, but the hook is also consulted from
// ShouldParseStreamBody before the streaming layer parses the path).
func pathAfterGateway(path string) string {
	if api, ok := httpproxy.PathAfterGateway(path); ok {
		return api
	}
	return path
}

// Options configures the host-specific knobs BuildHooks needs to assemble
// the three ProviderSpec hooks.
type Options struct {
	// BasicAuthUsername is the username placed in HTTP Basic Auth for git
	// smart-HTTP requests. Examples: "x-access-token" (GitHub),
	// "oauth2" (GitLab).
	BasicAuthUsername string

	// CredentialType is the credential.Type string the extractor will
	// accept (e.g. credential.TypeGitHubToken).
	CredentialType string

	// TokenField is the credential.Data key holding the token string
	// (e.g. "token" for GitHub, "access_token" for GitLab).
	TokenField string

	// DeriveGitURL transforms the configured REST API URL into the git
	// host URL. Host-specific: GitHub strips "api." and "/api/v3"; GitLab
	// uses the same host root for both protocols. When nil, BuildHooks
	// substitutes identity (the REST URL is also the git URL).
	DeriveGitURL func(restURL string) string
}

// Hooks bundles the three ProviderSpec hooks a git-aware provider must
// wire. Returned by BuildHooks.
type Hooks struct {
	ResolveUpstream          func(r *http.Request, providerURL string, state map[string]any) (httpproxy.Dispatch, bool)
	GetAuthRoleFromRequest   func(r *http.Request) string
	IsUnauthenticatedRequest func(r *http.Request, path string) bool
}

// BuildHooks returns the three ProviderSpec hooks parameterised by opts.
// If opts.DeriveGitURL is nil, identity is substituted — the REST URL is
// used unchanged as the git host URL.
func BuildHooks(opts Options) Hooks {
	deriveGitURL := opts.DeriveGitURL
	if deriveGitURL == nil {
		deriveGitURL = func(s string) string { return s }
	}

	extractor := func(req *logical.Request) (map[string]string, error) {
		if req.Credential == nil {
			return nil, fmt.Errorf("no credential available")
		}
		if req.Credential.Type != opts.CredentialType {
			return nil, fmt.Errorf("unsupported credential type: %s", req.Credential.Type)
		}
		tok := req.Credential.Data[opts.TokenField]
		if tok == "" {
			return nil, fmt.Errorf("credential missing %s field", opts.TokenField)
		}
		basic := base64.StdEncoding.EncodeToString([]byte(opts.BasicAuthUsername + ":" + tok))
		return map[string]string{"Authorization": "Basic " + basic}, nil
	}

	resolveUpstream := func(r *http.Request, providerURL string, state map[string]any) (httpproxy.Dispatch, bool) {
		if !IsSmartHTTPPath(pathAfterGateway(r.URL.Path)) {
			return httpproxy.Dispatch{}, false
		}
		maxBody, ok := state["git_max_body_size"].(int64)
		if !ok || maxBody <= 0 {
			maxBody = DefaultMaxBodySize
		}
		return httpproxy.Dispatch{
			UpstreamURL:        deriveGitURL(providerURL),
			ExtractCredentials: extractor,
			SkipDefaultAccept:  true,
			SkipDynamicHeaders: true,
			MaxBodySize:        maxBody,
			BypassBodyParsing:  true,
		}, true
	}

	roleFromBasicAuthUser := func(r *http.Request) string {
		if !IsSmartHTTPPath(pathAfterGateway(r.URL.Path)) {
			return ""
		}
		user, _, _ := r.BasicAuth()
		return user
	}

	// isUnauthenticatedGitProbe reports whether r is a Git smart-HTTP
	// probe that should pass through to the upstream without authentication.
	//
	// Git's smart-HTTP protocol always probes <repo>.git/info/refs once
	// without an Authorization header; it requires the server's
	// WWW-Authenticate response to know that it must retry with Basic Auth.
	// A bare 401 from us breaks the negotiation because clients never learn
	// what credential scheme to use. Letting the probe reach the upstream
	// lets the upstream return its own WWW-Authenticate: Basic challenge;
	// git then retries with <role>:<JWT>, which lands on the second-pass
	// code path where the provider's ExtractToken pulls the JWT from the
	// Basic password slot and normal auth runs.
	//
	// Returns false (so normal auth runs) when r is nil, when r carries any
	// Authorization header, or when the path is not a Git smart-HTTP
	// endpoint. The Authorization-header check looks redundant — core only
	// consults IsUnauthenticatedPath when ClientToken == "", which already
	// implies ExtractToken found no usable credential. But several edge
	// cases reach here with Authorization set yet ClientToken empty:
	// malformed Bearer ("Bearer " with no token), Basic with an empty
	// password slot, Negotiate (Kerberos) and other unrecognised schemes,
	// and Basic when X-SSL-Client-Cert is also present (some providers'
	// ExtractToken deliberately skips Basic in that case). Without this
	// guard those all silently get probe-passthrough; with it they fall
	// through to implicit-auth-fail → 401, which is the honest answer.
	isUnauthenticatedGitProbe := func(r *http.Request, path string) bool {
		if r == nil || r.Header.Get("Authorization") != "" {
			return false
		}
		return IsSmartHTTPPath(pathAfterGateway(path))
	}

	return Hooks{
		ResolveUpstream:          resolveUpstream,
		GetAuthRoleFromRequest:   roleFromBasicAuthUser,
		IsUnauthenticatedRequest: isUnauthenticatedGitProbe,
	}
}
