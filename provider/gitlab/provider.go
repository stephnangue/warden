package gitlab

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/provider/httpproxy"
)

var (
	sharedTransport        = httpproxy.NewTransport()
	transportCleanupCancel = httpproxy.StartCleanup(sharedTransport)
)

// extractToken extracts Warden token from PRIVATE-TOKEN, Authorization: Bearer, or X-Warden-Token headers.
func extractToken(r *http.Request) string {
	if token := r.Header.Get("PRIVATE-TOKEN"); token != "" {
		return token
	}
	authHeader := r.Header.Get("Authorization")
	if len(authHeader) > 7 && strings.EqualFold(authHeader[:7], "Bearer ") {
		return authHeader[7:]
	}
	if token := r.Header.Get("X-Warden-Token"); token != "" {
		return token
	}
	return ""
}

// validateGitLabAddress validates that the gitlab_address is a well-formed URL.
// Unlike other providers, GitLab allows HTTP for development instances.
func validateGitLabAddress(addr string) error {
	if addr == "" {
		return fmt.Errorf("gitlab_address is required")
	}
	parsed, err := url.Parse(addr)
	if err != nil {
		return fmt.Errorf("invalid gitlab_address: %w", err)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return fmt.Errorf("gitlab_address must use http:// or https:// scheme, got: %s", parsed.Scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("gitlab_address must include a host")
	}
	return nil
}

// Spec defines the GitLab provider configuration for the httpproxy framework.
var Spec = &httpproxy.ProviderSpec{
	Name:                 "gitlab",
	DefaultURL:           "", // GitLab requires explicit address
	URLConfigKey:         "gitlab_address",
	DefaultTimeout:       framework.DefaultTimeout,
	ParseStreamBody:      true,
	UserAgent:            "warden-gitlab-proxy",
	HelpText:             gitlabBackendHelp,
	ExtractCredentials:   httpproxy.TypedTokenExtractor(credential.TypeGitLabAccessToken, "access_token", "Authorization", "Bearer "),
	ExtractToken:         extractToken,
	ExtraHeadersToRemove: []string{"PRIVATE-TOKEN"},
	Transport:            sharedTransport,
	ShutdownTransport: func() {
		httpproxy.ShutdownTransport(sharedTransport, transportCleanupCancel)
	},
	ValidateExtraConfig: func(conf map[string]any) error {
		addr, ok := conf["gitlab_address"].(string)
		if !ok || addr == "" {
			return fmt.Errorf("gitlab_address is required")
		}
		return validateGitLabAddress(addr)
	},
}

// Factory creates a new GitLab provider backend.
var Factory = httpproxy.NewFactory(Spec)

const gitlabBackendHelp = `
The GitLab provider enables proxying requests to GitLab (SaaS or self-hosted)
with automatic credential management and access token injection.

Warden performs implicit authentication on every request and obtains a
GitLab access token from the credential manager — either a personal access
token (PAT) or an OAuth2 token depending on the source configuration — and
injects it as an Authorization: Bearer header in the proxied request. This
allows Warden to broker GitLab access without distributing long-lived tokens
to clients.

Unlike multi-host providers (AWS, GCP), the GitLab provider targets a single
GitLab instance configured via gitlab_address. All gateway requests are
forwarded to that instance.

The gateway path format is:
  /gitlab/gateway/{api-path}

The {api-path} is appended to the configured gitlab_address and forwarded
over HTTPS (or HTTP for development instances).

Examples:
  /gitlab/gateway/api/v4/projects
  /gitlab/gateway/api/v4/projects/123/repository/branches
  /gitlab/gateway/api/v4/groups/my-group/projects
  /gitlab/gateway/api/v4/projects/123/merge_requests
  /gitlab/gateway/api/v4/projects/123/pipelines

The role can be provided via the X-Warden-Role header, or embedded in
the URL path:
  /gitlab/role/{role}/gateway/{api-path}

Self-hosted GitLab instances are supported by setting gitlab_address to the
instance URL (e.g., "https://gitlab.example.com").

Configuration:
- gitlab_address: Base URL of the GitLab instance (required, e.g., "https://gitlab.com")
- max_body_size: Maximum request body size (default: 10MB, max: 100MB)
- timeout: Request timeout duration (e.g., '30s', '5m')
- auto_auth_path: Auth mount path for implicit authentication (e.g., 'auth/jwt/')
- default_role: Fallback role when not specified in the URL path
`
