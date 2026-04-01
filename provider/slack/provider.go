package slack

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

// slackBackend is the streaming backend for Slack provider operations
type slackBackend struct {
	*framework.StreamingBackend
	slackURL string // e.g., "https://slack.com/api"
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

// Factory creates a new Slack provider backend using the logical.Factory pattern
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &slackBackend{}

	// Create the streaming backend with gateway path for streaming
	b.StreamingBackend = &framework.StreamingBackend{
		StreamingPaths: []*framework.StreamingPath{
			{
				Pattern:         "gateway",
				Handler:         b.handleGatewayStreaming,
				HelpSynopsis:    "Slack Gateway proxy",
				HelpDescription: "Proxies requests to Slack API with bot token injection",
			},
			{
				Pattern:         "gateway/.*",
				Handler:         b.handleGatewayStreaming,
				HelpSynopsis:    "Slack Gateway proxy",
				HelpDescription: "Proxies requests to Slack API with bot token injection",
			},
			// Role-based gateway paths for implicit auth
			{
				Pattern:         "role/[^/]+/gateway",
				Handler:         b.handleTransparentGatewayStreaming,
				HelpSynopsis:    "Slack Transparent Gateway proxy",
				HelpDescription: "Proxies requests to Slack API with implicit JWT authentication",
			},
			{
				Pattern:         "role/[^/]+/gateway/.*",
				Handler:         b.handleTransparentGatewayStreaming,
				HelpSynopsis:    "Slack Transparent Gateway proxy",
				HelpDescription: "Proxies requests to Slack API with implicit JWT authentication",
			},
		},
		ParseStreamBody: true, // Enable policy evaluation on channel, text, etc.
		TransparentConfig: &framework.TransparentConfig{
			AutoAuthPath:    "",
			DefaultAuthRole: "",
		},
		Backend: &framework.Backend{
			Help:           slackBackendHelp,
			BackendType:    "slack",
			BackendClass:   logical.ClassProvider,
			TokenExtractor: extractToken,
			Paths:          b.paths(),
		},
	}

	// Set common fields
	b.Logger = conf.Logger.WithSubsystem("slack")
	b.StorageView = conf.StorageView

	// Initialize reverse proxy with Slack transport
	b.StreamingBackend.InitProxy(sharedTransport)

	// Register transport shutdown hook for process-level cleanup
	if conf.RegisterShutdownHook != nil {
		conf.RegisterShutdownHook("slack-transport", ShutdownHTTPTransport)
	}

	if err := b.StreamingBackend.Setup(ctx, conf); err != nil {
		return nil, err
	}

	// Set defaults
	b.MaxBodySize = framework.DefaultMaxBodySize
	b.Timeout = DefaultSlackTimeout
	b.slackURL = DefaultSlackURL

	// Apply configuration if provided
	if len(conf.Config) > 0 {
		if err := ValidateConfig(conf.Config); err != nil {
			return nil, fmt.Errorf("invalid configuration: %w", err)
		}
		parsedConfig := parseConfig(conf.Config)
		b.slackURL = strings.TrimRight(parsedConfig.SlackURL, "/")
		b.MaxBodySize = parsedConfig.MaxBodySize
		b.Timeout = parsedConfig.Timeout

		b.StreamingBackend.SetTransparentConfig(&framework.TransparentConfig{
			AutoAuthPath:    parsedConfig.AutoAuthPath,
			DefaultAuthRole: parsedConfig.DefaultAuthRole,
		})
	}

	return b, nil
}

// Initialize loads persisted config from storage
func (b *slackBackend) Initialize(ctx context.Context) error {
	if b.StorageView == nil {
		return nil
	}

	entry, err := b.StorageView.Get(ctx, "config")
	if err != nil {
		return fmt.Errorf("failed to read config from storage: %w", err)
	}
	if entry != nil {
		var config struct {
			SlackURL        string `json:"slack_url"`
			MaxBodySize     int64  `json:"max_body_size"`
			Timeout         string `json:"timeout"`
			AutoAuthPath    string `json:"auto_auth_path"`
			DefaultAuthRole string `json:"default_role"`
		}
		if err := entry.DecodeJSON(&config); err != nil {
			return fmt.Errorf("failed to decode config: %w", err)
		}
		if config.SlackURL != "" {
			b.slackURL = strings.TrimRight(config.SlackURL, "/")
		}
		b.MaxBodySize = config.MaxBodySize
		if config.Timeout != "" {
			if timeout, err := time.ParseDuration(config.Timeout); err == nil {
				b.Timeout = timeout
			}
		}

		b.StreamingBackend.SetTransparentConfig(&framework.TransparentConfig{
			AutoAuthPath:    config.AutoAuthPath,
			DefaultAuthRole: config.DefaultAuthRole,
		})
	} else {
		// No persisted config — persist defaults
		tc := b.TransparentConfig
		defaultEntry, err := sdklogical.StorageEntryJSON("config", map[string]any{
			"slack_url":      b.slackURL,
			"max_body_size":  b.MaxBodySize,
			"timeout":        b.Timeout.String(),
			"auto_auth_path": tc.AutoAuthPath,
			"default_role":   tc.DefaultAuthRole,
		})
		if err != nil {
			return fmt.Errorf("failed to create default config entry: %w", err)
		}
		if err := b.StorageView.Put(ctx, defaultEntry); err != nil {
			return fmt.Errorf("failed to persist default config: %w", err)
		}
		b.Logger.Info("persisted default configuration for new Slack provider")
	}
	return nil
}

// paths returns the configuration paths for the Slack provider
func (b *slackBackend) paths() []*framework.Path {
	return []*framework.Path{
		b.pathConfig(),
	}
}

// handleGatewayStreaming handles streaming gateway requests
func (b *slackBackend) handleGatewayStreaming(ctx context.Context, req *logical.Request, fd *framework.FieldData) error {
	b.handleGateway(ctx, req)
	return nil
}

// handleTransparentGatewayStreaming handles gateway requests with implicit auth.
// The implicit auth has already been performed by the core request handler.
func (b *slackBackend) handleTransparentGatewayStreaming(ctx context.Context, req *logical.Request, fd *framework.FieldData) error {
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
func (b *slackBackend) SensitiveConfigFields() []string {
	return []string{}
}

const slackBackendHelp = `
The Slack provider enables proxying requests to the Slack Web API with
automatic credential management and bot token injection.

Clients authenticate to Warden with a session token (via X-Warden-Token or
Authorization: Bearer header). The provider obtains a Slack bot token from
the credential manager and injects it into the proxied request's Authorization
header. This allows Warden to broker Slack access without exposing bot
tokens to clients.

The gateway path format is:
  /slack/gateway/{slack-method}

Examples:
  /slack/gateway/chat.postMessage
  /slack/gateway/conversations.list
  /slack/gateway/conversations.history
  /slack/gateway/auth.test
  /slack/gateway/users.info

Request body parsing is enabled, allowing policies to evaluate Slack request
fields such as channel, text, user, and as_user. This enables fine-grained
access control — for example, restricting which channels a role can post to.

Implicit JWT authentication via role-based paths,
eliminating the need for clients to perform an explicit Warden login:
  /slack/role/{role}/gateway/{slack-method}

The core extracts the role from the URL, performs implicit JWT auth against
the configured auth mount, and issues a short-lived token for the request.

Configuration:
- slack_url: Slack API base URL (default: https://slack.com/api)
- max_body_size: Maximum request body size (default: 10MB, max: 100MB)
- timeout: Request timeout duration (default: 30s)
- auto_auth_path: Auth mount path for implicit authentication (e.g., 'auth/jwt/')
- default_role: Fallback role when not specified in the URL path
`
