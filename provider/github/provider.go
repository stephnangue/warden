package github

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

// githubBackend is the streaming backend for GitHub provider operations
type githubBackend struct {
	*framework.StreamingBackend
	githubURL  string // e.g., "https://api.github.com" or "https://github.example.com/api/v3"
	apiVersion string // e.g., "2022-11-28"
}

// extractToken extracts Warden token from Authorization: Bearer or X-Warden-Token headers
func extractToken(r *http.Request) string {
	// First, check X-Warden-Token header (explicit Warden token)
	if token := r.Header.Get("X-Warden-Token"); token != "" {
		return token
	}

	// Then check Authorization header for Bearer token
	authHeader := r.Header.Get("Authorization")
	if len(authHeader) > 7 && strings.EqualFold(authHeader[:7], "Bearer ") {
		return authHeader[7:]
	}

	return ""
}

// Factory creates a new GitHub provider backend using the logical.Factory pattern
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &githubBackend{}

	// Create the streaming backend with gateway path for streaming
	b.StreamingBackend = &framework.StreamingBackend{
		StreamingPaths: []*framework.StreamingPath{
			{
				Pattern:         "gateway",
				Handler:         b.handleGatewayStreaming,
				HelpSynopsis:    "GitHub Gateway proxy",
				HelpDescription: "Proxies requests to GitHub API with token injection",
			},
			{
				Pattern:         "gateway/.*",
				Handler:         b.handleGatewayStreaming,
				HelpSynopsis:    "GitHub Gateway proxy",
				HelpDescription: "Proxies requests to GitHub API with token injection",
			},
			// Transparent mode: role-based gateway paths
			{
				Pattern:         "role/[^/]+/gateway",
				Handler:         b.handleTransparentGatewayStreaming,
				HelpSynopsis:    "GitHub Transparent Gateway proxy",
				HelpDescription: "Proxies requests to GitHub API with implicit JWT authentication",
			},
			{
				Pattern:         "role/[^/]+/gateway/.*",
				Handler:         b.handleTransparentGatewayStreaming,
				HelpSynopsis:    "GitHub Transparent Gateway proxy",
				HelpDescription: "Proxies requests to GitHub API with implicit JWT authentication",
			},
		},
		TransparentConfig: &framework.TransparentConfig{
			Enabled:      false,
			AutoAuthPath: "",
			DefaultRole:  "",
		},
		Backend: &framework.Backend{
			Help:           githubBackendHelp,
			BackendType:    "github",
			BackendClass:   logical.ClassProvider,
			TokenExtractor: extractToken,
			Paths:          b.paths(),
		},
	}

	// Set common fields
	b.Logger = conf.Logger.WithSubsystem("github")
	b.StorageView = conf.StorageView

	// Initialize reverse proxy with GitHub transport
	b.StreamingBackend.InitProxy(sharedTransport)

	// Register transport shutdown hook for process-level cleanup
	if conf.RegisterShutdownHook != nil {
		conf.RegisterShutdownHook("github-transport", ShutdownHTTPTransport)
	}

	// Set defaults
	b.MaxBodySize = framework.DefaultMaxBodySize
	b.Timeout = framework.DefaultTimeout
	b.githubURL = DefaultGitHubURL
	b.apiVersion = DefaultAPIVersion

	// Apply configuration if provided
	if len(conf.Config) > 0 {
		if err := ValidateConfig(conf.Config); err != nil {
			return nil, fmt.Errorf("invalid configuration: %w", err)
		}
		parsedConfig := parseConfig(conf.Config)
		b.githubURL = strings.TrimRight(parsedConfig.GitHubURL, "/")
		b.apiVersion = parsedConfig.APIVersion
		b.MaxBodySize = parsedConfig.MaxBodySize
		b.Timeout = parsedConfig.Timeout

		b.StreamingBackend.SetTransparentConfig(&framework.TransparentConfig{
			Enabled:      parsedConfig.TransparentMode,
			AutoAuthPath: parsedConfig.AutoAuthPath,
			DefaultRole:  parsedConfig.DefaultRole,
		})
	}

	return b, nil
}

// Initialize loads persisted config from storage
func (b *githubBackend) Initialize(ctx context.Context) error {
	if b.StorageView == nil {
		return nil
	}

	entry, err := b.StorageView.Get(ctx, "config")
	if err != nil {
		return fmt.Errorf("failed to read config from storage: %w", err)
	}
	if entry != nil {
		var config struct {
			GitHubURL       string `json:"github_url"`
			MaxBodySize     int64  `json:"max_body_size"`
			Timeout         string `json:"timeout"`
			APIVersion      string `json:"api_version"`
			TransparentMode bool   `json:"transparent_mode"`
			AutoAuthPath    string `json:"auto_auth_path"`
			DefaultRole     string `json:"default_role"`
		}
		if err := entry.DecodeJSON(&config); err != nil {
			return fmt.Errorf("failed to decode config: %w", err)
		}
		if config.GitHubURL != "" {
			b.githubURL = strings.TrimRight(config.GitHubURL, "/")
		}
		if config.APIVersion != "" {
			b.apiVersion = config.APIVersion
		}
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
	} else {
		// No persisted config — persist defaults
		tc := b.TransparentConfig
		defaultEntry, err := sdklogical.StorageEntryJSON("config", map[string]any{
			"github_url":       b.githubURL,
			"max_body_size":    b.MaxBodySize,
			"timeout":          b.Timeout.String(),
			"api_version":      b.apiVersion,
			"transparent_mode": tc.Enabled,
			"auto_auth_path":   tc.AutoAuthPath,
			"default_role":     tc.DefaultRole,
		})
		if err != nil {
			return fmt.Errorf("failed to create default config entry: %w", err)
		}
		if err := b.StorageView.Put(ctx, defaultEntry); err != nil {
			return fmt.Errorf("failed to persist default config: %w", err)
		}
		b.Logger.Info("persisted default configuration for new GitHub provider")
	}
	return nil
}

// paths returns the configuration paths for the GitHub provider
func (b *githubBackend) paths() []*framework.Path {
	return []*framework.Path{
		b.pathConfig(),
	}
}

// handleGatewayStreaming handles streaming gateway requests
func (b *githubBackend) handleGatewayStreaming(ctx context.Context, req *logical.Request, fd *framework.FieldData) error {
	b.handleGateway(ctx, req)
	return nil
}

// handleTransparentGatewayStreaming handles transparent mode gateway requests.
// The implicit auth has already been performed by the core request handler.
func (b *githubBackend) handleTransparentGatewayStreaming(ctx context.Context, req *logical.Request, fd *framework.FieldData) error {
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
func (b *githubBackend) SensitiveConfigFields() []string {
	return []string{}
}

const githubBackendHelp = `
The GitHub provider enables proxying requests to the GitHub REST API with
automatic credential management and token injection.

Clients authenticate to Warden with a session token (via X-Warden-Token or
Authorization: Bearer header). The provider obtains a GitHub token from the
credential manager and injects it into the proxied request's Authorization
header. This allows Warden to broker GitHub API access without exposing
personal access tokens or app credentials to clients.

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

Transparent mode allows implicit JWT authentication via role-based paths,
eliminating the need for clients to perform an explicit Warden login:
  /github/role/{role}/gateway/{api-path}

The core extracts the role from the URL, performs implicit JWT auth against
the configured auth mount, and issues a short-lived token for the request.

Configuration:
- github_url: GitHub API base URL (default: https://api.github.com)
- max_body_size: Maximum request body size (default: 10MB, max: 100MB)
- timeout: Request timeout duration (e.g., '30s', '5m')
- transparent_mode: Enable implicit JWT authentication (default: false)
- auto_auth_path: JWT auth mount path for transparent mode (e.g., 'auth/jwt/')
- default_role: Fallback role when not specified in the URL path
`
