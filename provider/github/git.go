package github

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/sdk/httpproxy"
)

// Git smart-HTTP support: the github provider mount carries two protocols
// at once. REST paths (/repos, /user, /orgs, ...) proxy to api.github.com
// with a Bearer token. Git smart-HTTP paths (<owner>/<repo>.git/info/refs,
// .git/git-upload-pack, .git/git-receive-pack) proxy to github.com with
// HTTP Basic Auth carrying the PAT as the password.
//
// The dispatch is driven by ResolveUpstream + GetAuthRoleFromRequest on
// Spec, so REST behaviour is unchanged for callers that don't hit a
// Git-shaped path.

// DefaultGitMaxBodySize is the default cap on Git request bodies (2 GiB).
// Big enough for most pushes; operators with larger repos bump it via the
// git_max_body_size config field.
const DefaultGitMaxBodySize int64 = 2 * 1024 * 1024 * 1024

// MinGitMaxBodySize is the lower bound for git_max_body_size validation.
// Below this, Git clones of even trivial repos start failing.
const MinGitMaxBodySize int64 = 1 * 1024 * 1024 // 1 MiB

// MaxGitMaxBodySize is the upper bound for git_max_body_size validation.
// Repos larger than this should be using LFS-aware infrastructure rather
// than the gateway.
const MaxGitMaxBodySize int64 = 10 * 1024 * 1024 * 1024 // 10 GiB

// gitSmartHTTPSuffixes are the smart-HTTP endpoint suffixes that identify a
// Git-protocol request inside the gateway path.
var gitSmartHTTPSuffixes = []string{
	".git/info/refs",
	".git/git-upload-pack",
	".git/git-receive-pack",
}

// isGitSmartHTTPPath reports whether apiPath (the portion of the URL after
// "/gateway") is a Git smart-HTTP endpoint.
func isGitSmartHTTPPath(apiPath string) bool {
	for _, suffix := range gitSmartHTTPSuffixes {
		if strings.HasSuffix(apiPath, suffix) {
			return true
		}
	}
	return false
}

// pathAfterGateway extracts the API-shaped path slice from a routed gateway
// request URL. Wraps the SDK helper with a fall-back to the input when no
// "/gateway" segment is present (defensive — routed gateway requests always
// contain one, but ResolveUpstream is also called from ShouldParseStreamBody
// before the streaming layer parses the path).
func pathAfterGateway(path string) string {
	if api, ok := httpproxy.PathAfterGateway(path); ok {
		return api
	}
	return path
}

// deriveGitURL derives the Git host URL from the configured REST API URL.
//
//	https://api.github.com           -> https://github.com
//	https://ghe.example.com/api/v3   -> https://ghe.example.com
//	(GHE host that does not match)   -> input with /api/v3 suffix stripped
//
// Trailing slashes on the input are tolerated.
func deriveGitURL(apiURL string) string {
	apiURL = strings.TrimRight(apiURL, "/")
	if apiURL == "https://api.github.com" || apiURL == "http://api.github.com" {
		return strings.Replace(apiURL, "://api.github.com", "://github.com", 1)
	}
	if strings.HasSuffix(apiURL, "/api/v3") {
		return strings.TrimSuffix(apiURL, "/api/v3")
	}
	return apiURL
}

// gitCredentialExtractor formats the GitHub PAT as HTTP Basic Auth using
// "x-access-token" as the username — the credential helper convention
// GitHub publishes for both PATs and App installation tokens.
func gitCredentialExtractor(req *logical.Request) (map[string]string, error) {
	if req.Credential == nil {
		return nil, fmt.Errorf("no credential available")
	}
	if req.Credential.Type != credential.TypeGitHubToken {
		return nil, fmt.Errorf("unsupported credential type: %s", req.Credential.Type)
	}
	tok := req.Credential.Data["token"]
	if tok == "" {
		return nil, fmt.Errorf("credential missing %s field", "token")
	}
	basic := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + tok))
	return map[string]string{"Authorization": "Basic " + basic}, nil
}

// resolveGitUpstream is the Spec.ResolveUpstream hook. It returns a Dispatch
// that routes Git smart-HTTP paths to the Git host with Basic Auth, raises
// the body cap to the configured git_max_body_size, suppresses dynamic
// header injection (X-GitHub-Api-Version is irrelevant for Git endpoints),
// and bypasses body parsing (binary pack-files would be wasteful to parse).
//
// For non-Git paths, returns ok=false so the spec defaults apply unchanged
// — REST callers see no behavioural change.
func resolveGitUpstream(r *http.Request, providerURL string, state map[string]any) (httpproxy.Dispatch, bool) {
	if !isGitSmartHTTPPath(pathAfterGateway(r.URL.Path)) {
		return httpproxy.Dispatch{}, false
	}
	maxBody, ok := state["git_max_body_size"].(int64)
	if !ok || maxBody <= 0 {
		maxBody = DefaultGitMaxBodySize
	}
	return httpproxy.Dispatch{
		UpstreamURL:        deriveGitURL(providerURL),
		ExtractCredentials: gitCredentialExtractor,
		SkipDefaultAccept:  true,
		SkipDynamicHeaders: true,
		MaxBodySize:        maxBody,
		BypassBodyParsing:  true,
	}, true
}

// roleFromBasicAuthUser is the Spec.GetAuthRoleFromRequest hook. On Git
// smart-HTTP paths, the Basic Auth username carries the Warden role. On
// non-Git paths, returns ("", true) — "transparent yes, no role from me"
// — so the existing default_role / path role / X-Warden-Role flow is
// untouched for REST callers.
func roleFromBasicAuthUser(r *http.Request) (string, bool) {
	if !isGitSmartHTTPPath(pathAfterGateway(r.URL.Path)) {
		return "", true
	}
	user, _, ok := r.BasicAuth()
	if !ok || user == "" {
		return "", true
	}
	return user, true
}
