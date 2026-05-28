package github

import (
	"net/http"
	"strings"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/provider/sdk/githttp"
	"github.com/stephnangue/warden/provider/sdk/httpproxy"
)

// DefaultGitHubURL is the default GitHub API base URL
const DefaultGitHubURL = "https://api.github.com"

// DefaultAPIVersion is the default GitHub REST API version
const DefaultAPIVersion = "2022-11-28"

// extractToken extracts the Warden token from one of:
//  1. X-Warden-Token header
//  2. Authorization: Bearer <token>
//  3. HTTP Basic Auth password (Git smart-HTTP carries the JWT this way)
//
// The Basic Auth branch is suppressed when X-SSL-Client-Cert is present:
// cert-based implicit auth takes precedence in the core flow, and the Git
// protocol requires a placeholder password slot that the JWT validator
// would otherwise reject. Reading the placeholder would actively harm
// correctness for cert-authenticated clients.
func extractToken(r *http.Request) string {
	if token := r.Header.Get("X-Warden-Token"); token != "" {
		return token
	}
	authHeader := r.Header.Get("Authorization")
	if len(authHeader) > 7 && strings.EqualFold(authHeader[:7], "Bearer ") {
		return authHeader[7:]
	}
	if r.Header.Get("X-SSL-Client-Cert") == "" {
		if _, pwd, ok := r.BasicAuth(); ok && pwd != "" {
			return pwd
		}
	}
	return ""
}

// Spec defines the GitHub provider configuration for the httpproxy framework.
var Spec = &httpproxy.ProviderSpec{
	Name:               "github",
	DefaultURL:         DefaultGitHubURL,
	URLConfigKey:       "github_url",
	DefaultTimeout:     framework.DefaultTimeout,
	ParseStreamBody:    true,
	UserAgent:          "warden-github-proxy",
	HelpText:           githubBackendHelp,
	ExtractCredentials: httpproxy.TypedTokenExtractor(credential.TypeGitHubToken, "token", "Authorization", "token "),
	ExtractToken:       extractToken,
	DefaultAccept:      "application/vnd.github+json",
	ExtraConfigFields: map[string]*framework.FieldSchema{
		"api_version": {
			Type:        framework.TypeString,
			Description: "GitHub REST API version for X-GitHub-Api-Version header (default: 2022-11-28)",
			Default:     DefaultAPIVersion,
		},
		"git_max_body_size": githttp.MaxBodySizeField(),
	},
	DynamicHeaders: func(state map[string]any) map[string]string {
		ver, _ := state["api_version"].(string)
		if ver == "" {
			ver = DefaultAPIVersion
		}
		return map[string]string{"X-GitHub-Api-Version": ver}
	},
	OnConfigRead: func(state map[string]any) map[string]any {
		ver, _ := state["api_version"].(string)
		if ver == "" {
			ver = DefaultAPIVersion
		}
		return map[string]any{
			"api_version":       ver,
			"git_max_body_size": githttp.ReadMaxBodySize(state),
		}
	},
	OnConfigWrite: func(d *framework.FieldData, state map[string]any) (map[string]any, error) {
		// Validate before mutating so a rejected write leaves no partial
		// state for the caller to observe.
		if err := githttp.WriteMaxBodySize(d, state); err != nil {
			return nil, err
		}
		if val, ok := d.GetOk("api_version"); ok {
			ver := val.(string)
			if ver != "" {
				state["api_version"] = ver
			}
		}
		return state, nil
	},
	OnInitialize: func(config map[string]any, state map[string]any) map[string]any {
		if ver, ok := config["api_version"].(string); ok && ver != "" {
			state["api_version"] = ver
		} else {
			state["api_version"] = DefaultAPIVersion
		}
		githttp.InitializeMaxBodySize(config, state)
		return state
	},
	ResolveUpstream:          gitHooks.ResolveUpstream,
	GetAuthRoleFromRequest:   gitHooks.GetAuthRoleFromRequest,
	IsUnauthenticatedRequest: gitHooks.IsUnauthenticatedRequest,
}

// Factory creates a new GitHub provider backend.
var Factory = httpproxy.NewFactory(Spec)

const githubBackendHelp = `
The GitHub provider proxies both the GitHub REST API and Git smart-HTTP
(clone/fetch/push) with automatic credential management. The mount
dispatches per-request based on path shape:

  REST paths (/repos, /user, /orgs, ...) → api.github.com with
    Authorization: token <PAT>.

  Git smart-HTTP paths (<owner>/<repo>.git/info/refs,
    .git/git-upload-pack, .git/git-receive-pack) → github.com (or the
    GHE host derived from github_url) with HTTP Basic Auth carrying
    x-access-token:<PAT> as the credential.

Warden performs implicit authentication on every request and obtains a
GitHub token from the credential manager. Clients never hold a PAT.

The REST gateway path format is:
  /github/gateway/{api-path}

Examples:
  /github/gateway/repos/owner/repo
  /github/gateway/user
  /github/gateway/orgs/myorg/repos
  /github/gateway/repos/owner/repo/pulls?state=open

The Git clone URL carries the Warden role in the Basic Auth username
and the Warden JWT in the password:

  git clone https://<role>:$JWT@<warden-addr>/v1/github/gateway/<owner>/<repo>.git

Git's credential helpers cache on URL + username, so each role gets a
distinct credential entry. Cert-auth clients pass any placeholder in
the password slot; the token extractor skips the placeholder when
X-SSL-Client-Cert is present.

For GitHub Enterprise Server:
  Configure github_url to point to your GHE instance API endpoint
  (e.g., https://github.example.com/api/v3). The Git host is derived
  automatically (e.g., https://github.example.com).

The role can be provided via the X-Warden-Role header, embedded in
the URL path (/github/role/{role}/gateway/{api-path}), carried in
the Basic Auth username (Git smart-HTTP requests only), or defaulted
by default_role. Precedence: X-Warden-Role > path role > Basic Auth
username > default_role.

Header-routed alternative: clients that want a URL without the
/v1/github/gateway/ prefix can send X-Warden-Provider: github (and
optionally X-Warden-Role) and let Warden synthesise the canonical
path from the literal upstream path. For Git, set both via
http.extraheader at clone time:

  git -c http.extraheader="X-Warden-Provider: github" \
      clone https://<role>:$JWT@<warden-addr>/<owner>/<repo>.git

http.extraheader persists into .git/config, so subsequent fetch/pull/push
carry the header automatically.

Configuration:
- github_url: GitHub API base URL (default: https://api.github.com)
- api_version: GitHub REST API version header (default: 2022-11-28)
- git_max_body_size: Cap on Git request bodies in bytes
    (default: 2 GiB, range: 1 MiB to 10 GiB)
- max_body_size: Cap on REST request bodies (default: 10MB, max: 100MB).
    Do not raise to accommodate Git pushes — git_max_body_size is the
    knob for that.
- timeout: Request timeout duration (e.g., '30s', '5m'). Tune up for
    large Git pushes.
- auto_auth_path: Auth mount path for implicit authentication (e.g.,
    'auth/jwt/')
- default_role: Fallback role when not specified by header or URL path
`
