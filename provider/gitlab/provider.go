package gitlab

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

// gitlabBackend is the streaming backend for GitLab provider operations
type gitlabBackend struct {
	*framework.StreamingBackend
	gitlabAddress string // e.g., "https://gitlab.com" or "https://gitlab.example.com"
}

// extractToken extracts Warden token from PRIVATE-TOKEN, Authorization: Bearer, or X-Warden-Token headers
func extractToken(r *http.Request) string {
	// Primary: PRIVATE-TOKEN header (standard GitLab header)
	if token := r.Header.Get("PRIVATE-TOKEN"); token != "" {
		return token
	}
	// Secondary: Authorization: Bearer
	authHeader := r.Header.Get("Authorization")
	if len(authHeader) > 7 && strings.EqualFold(authHeader[:7], "Bearer ") {
		return authHeader[7:]
	}
	// Fallback: X-Warden-Token
	if token := r.Header.Get("X-Warden-Token"); token != "" {
		return token
	}
	return ""
}

// Factory creates a new GitLab provider backend using the logical.Factory pattern
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &gitlabBackend{}

	// Create the streaming backend with gateway path for streaming
	b.StreamingBackend = &framework.StreamingBackend{
		StreamingPaths: []*framework.StreamingPath{
			{
				Pattern:         "gateway",
				Handler:         b.handleGatewayStreaming,
				HelpSynopsis:    "GitLab Gateway proxy",
				HelpDescription: "Proxies requests to GitLab with token injection",
			},
			{
				Pattern:         "gateway/.*",
				Handler:         b.handleGatewayStreaming,
				HelpSynopsis:    "GitLab Gateway proxy",
				HelpDescription: "Proxies requests to GitLab with token injection",
			},
			// Transparent mode: role-based gateway paths
			{
				Pattern:         "role/[^/]+/gateway",
				Handler:         b.handleTransparentGatewayStreaming,
				HelpSynopsis:    "GitLab Transparent Gateway proxy",
				HelpDescription: "Proxies requests to GitLab with implicit JWT authentication",
			},
			{
				Pattern:         "role/[^/]+/gateway/.*",
				Handler:         b.handleTransparentGatewayStreaming,
				HelpSynopsis:    "GitLab Transparent Gateway proxy",
				HelpDescription: "Proxies requests to GitLab with implicit JWT authentication",
			},
		},
		TransparentConfig: &framework.TransparentConfig{
			Enabled:      false,
			AutoAuthPath: "",
			DefaultRole:  "",
		},
		Backend: &framework.Backend{
			Help:           gitlabBackendHelp,
			BackendType:    "gitlab",
			BackendClass:   logical.ClassProvider,
			TokenExtractor: extractToken,
			Paths:          b.paths(),
		},
	}

	// Set common fields
	b.Logger = conf.Logger.WithSubsystem("gitlab")
	b.StorageView = conf.StorageView

	// Initialize reverse proxy with GitLab transport
	b.StreamingBackend.InitProxy(sharedTransport)

	// Register transport shutdown hook for process-level cleanup
	if conf.RegisterShutdownHook != nil {
		conf.RegisterShutdownHook("gitlab-transport", ShutdownHTTPTransport)
	}

	// Set defaults
	b.MaxBodySize = framework.DefaultMaxBodySize
	b.Timeout = framework.DefaultTimeout

	// Apply configuration if provided
	if len(conf.Config) > 0 {
		if err := ValidateConfig(conf.Config); err != nil {
			return nil, fmt.Errorf("invalid configuration: %w", err)
		}
		parsedConfig := parseConfig(conf.Config)
		b.gitlabAddress = parsedConfig.GitLabAddress
		b.MaxBodySize = parsedConfig.MaxBodySize
		b.Timeout = parsedConfig.Timeout
	}

	return b, nil
}

// Initialize loads persisted config from storage
func (b *gitlabBackend) Initialize(ctx context.Context) error {
	if b.StorageView == nil {
		return nil
	}

	entry, err := b.StorageView.Get(ctx, "config")
	if err != nil {
		return fmt.Errorf("failed to read config from storage: %w", err)
	}
	if entry != nil {
		var config struct {
			GitLabAddress   string `json:"gitlab_address"`
			MaxBodySize     int64  `json:"max_body_size"`
			Timeout         string `json:"timeout"`
			TransparentMode bool   `json:"transparent_mode"`
			AutoAuthPath    string `json:"auto_auth_path"`
			DefaultRole     string `json:"default_role"`
		}
		if err := entry.DecodeJSON(&config); err != nil {
			return fmt.Errorf("failed to decode config: %w", err)
		}
		b.gitlabAddress = config.GitLabAddress
		b.MaxBodySize = config.MaxBodySize
		if config.Timeout != "" {
			if timeout, err := time.ParseDuration(config.Timeout); err == nil {
				b.Timeout = timeout
			}
		}

		b.StreamingBackend.SetTransparentConfig(&framework.TransparentConfig{
			Enabled:      config.TransparentMode,
			AutoAuthPath: config.AutoAuthPath,
			DefaultRole:  config.DefaultRole,
		})
	}
	return nil
}

// paths returns the configuration paths for the GitLab provider
func (b *gitlabBackend) paths() []*framework.Path {
	return []*framework.Path{
		b.pathConfig(),
	}
}

// handleGatewayStreaming handles streaming gateway requests
func (b *gitlabBackend) handleGatewayStreaming(ctx context.Context, req *logical.Request, fd *framework.FieldData) error {
	b.handleGateway(ctx, req)
	return nil
}

// handleTransparentGatewayStreaming handles transparent mode gateway requests.
// The implicit auth has already been performed by the core request handler.
func (b *gitlabBackend) handleTransparentGatewayStreaming(ctx context.Context, req *logical.Request, fd *framework.FieldData) error {
	if !b.StreamingBackend.IsTransparentMode() {
		http.Error(req.ResponseWriter, "Transparent mode not enabled", http.StatusForbidden)
		return nil
	}

	// Rewrite the path: /role/{role}/gateway/... -> /gateway/...
	req.Path = b.StreamingBackend.RewriteTransparentPath(req.Path)

	// Also update the HTTP request URL path for the proxy
	if req.HTTPRequest != nil && req.HTTPRequest.URL != nil {
		req.HTTPRequest.URL.Path = b.StreamingBackend.RewriteTransparentPath(req.HTTPRequest.URL.Path)
	}

	// Delegate to standard gateway handler
	b.handleGateway(ctx, req)
	return nil
}

// SensitiveConfigFields returns the list of config fields that should be masked in output
func (b *gitlabBackend) SensitiveConfigFields() []string {
	return []string{}
}

const gitlabBackendHelp = `
The GitLab provider enables proxying requests to GitLab (SaaS or self-hosted)
with automatic credential management and access token injection.

Clients authenticate to Warden with a session token (via PRIVATE-TOKEN,
Authorization: Bearer, or X-Warden-Token header). The provider obtains a
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

Transparent mode allows implicit JWT authentication via role-based paths,
eliminating the need for clients to perform an explicit Warden login:
  /gitlab/role/{role}/gateway/{api-path}

The core extracts the role from the URL, performs implicit JWT auth against
the configured auth mount, and issues a short-lived token for the request.

Self-hosted GitLab instances are supported by setting gitlab_address to the
instance URL (e.g., "https://gitlab.example.com").

Configuration:
- gitlab_address: Base URL of the GitLab instance (required, e.g., "https://gitlab.com")
- max_body_size: Maximum request body size (default: 10MB, max: 100MB)
- timeout: Request timeout duration (e.g., '30s', '5m')
- transparent_mode: Enable implicit JWT authentication (default: false)
- auto_auth_path: JWT auth mount path for transparent mode (e.g., 'auth/jwt/')
- default_role: Fallback role when not specified in the URL path
`
