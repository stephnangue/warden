package github

import (
	"net/http"
	"strings"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/provider/httpproxy"
)

// DefaultGitHubURL is the default GitHub API base URL
const DefaultGitHubURL = "https://api.github.com"

// DefaultAPIVersion is the default GitHub REST API version
const DefaultAPIVersion = "2022-11-28"

var (
	sharedTransport        = httpproxy.NewTransport()
	transportCleanupCancel = httpproxy.StartCleanup(sharedTransport)
)

// extractToken extracts Warden token from Authorization: Bearer or X-Warden-Token headers.
func extractToken(r *http.Request) string {
	if token := r.Header.Get("X-Warden-Token"); token != "" {
		return token
	}
	authHeader := r.Header.Get("Authorization")
	if len(authHeader) > 7 && strings.EqualFold(authHeader[:7], "Bearer ") {
		return authHeader[7:]
	}
	return ""
}

// Spec defines the GitHub provider configuration for the httpproxy framework.
var Spec = &httpproxy.ProviderSpec{
	Name:               "github",
	DefaultURL:         DefaultGitHubURL,
	URLConfigKey:       "github_url",
	DefaultTimeout:     framework.DefaultTimeout,
	ParseStreamBody:    false,
	UserAgent:          "warden-github-proxy",
	HelpText:           githubBackendHelp,
	ExtractCredentials: httpproxy.TypedTokenExtractor(credential.TypeGitHubToken, "token", "Authorization", "token "),
	ExtractToken:       extractToken,
	DefaultAccept:      "application/vnd.github+json",
	Transport:          sharedTransport,
	ShutdownTransport: func() {
		httpproxy.ShutdownTransport(sharedTransport, transportCleanupCancel)
	},
	ExtraConfigFields: map[string]*framework.FieldSchema{
		"api_version": {
			Type:        framework.TypeString,
			Description: "GitHub REST API version for X-GitHub-Api-Version header (default: 2022-11-28)",
			Default:     DefaultAPIVersion,
		},
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
		return map[string]any{"api_version": ver}
	},
	OnConfigWrite: func(d *framework.FieldData, state map[string]any) (map[string]any, error) {
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
		return state
	},
}

// Factory creates a new GitHub provider backend.
var Factory = httpproxy.NewFactory(Spec)

const githubBackendHelp = `
The GitHub provider enables proxying requests to the GitHub REST API with
automatic credential management and token injection.

Warden performs implicit authentication on every request and obtains a
GitHub token from the credential manager, injecting it into the proxied
request's Authorization header. This allows Warden to broker GitHub API
access without exposing personal access tokens or app credentials to clients.

The gateway path format is:
  /github/gateway/{api-path}

Unlike cloud providers (AWS, Azure, GCP) that proxy to different hostnames,
the GitHub provider always proxies to a single API base URL (api.github.com
by default, or a configured GitHub Enterprise Server endpoint). The
{api-path} maps directly to the GitHub REST API path.

Examples:
  /github/gateway/repos/owner/repo
  /github/gateway/user
  /github/gateway/orgs/myorg/repos
  /github/gateway/repos/owner/repo/pulls?state=open

For GitHub Enterprise Server:
  Configure github_url to point to your GHE instance API endpoint
  (e.g., https://github.example.com/api/v3).

The role can be provided via the X-Warden-Role header, or embedded in
the URL path:
  /github/role/{role}/gateway/{api-path}

Configuration:
- github_url: GitHub API base URL (default: https://api.github.com)
- max_body_size: Maximum request body size (default: 10MB, max: 100MB)
- timeout: Request timeout duration (e.g., '30s', '5m')
- auto_auth_path: Auth mount path for implicit authentication (e.g., 'auth/jwt/')
- default_role: Fallback role when not specified in the URL path
`
