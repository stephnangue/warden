package anthropic

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

// anthropicBackend is the streaming backend for Anthropic provider operations
type anthropicBackend struct {
	*framework.StreamingBackend
	anthropicURL string // e.g., "https://api.anthropic.com"
}

// extractToken extracts Warden token from X-Warden-Token, x-api-key, or Authorization: Bearer headers.
// Anthropic clients typically send credentials via x-api-key, so we accept that as a Warden token source.
func extractToken(r *http.Request) string {
	// First, check X-Warden-Token header (explicit Warden token)
	if token := r.Header.Get("X-Warden-Token"); token != "" {
		return token
	}

	// Then check x-api-key header (Anthropic SDK default)
	if token := r.Header.Get("x-api-key"); token != "" {
		return token
	}

	// Then check Authorization header for Bearer token
	authHeader := r.Header.Get("Authorization")
	if len(authHeader) > 7 && strings.EqualFold(authHeader[:7], "Bearer ") {
		return authHeader[7:]
	}

	return ""
}

// Factory creates a new Anthropic provider backend using the logical.Factory pattern
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &anthropicBackend{}

	// Create the streaming backend with gateway path for streaming
	b.StreamingBackend = &framework.StreamingBackend{
		StreamingPaths: []*framework.StreamingPath{
			{
				Pattern:         "gateway",
				Handler:         b.handleGatewayStreaming,
				HelpSynopsis:    "Anthropic Gateway proxy",
				HelpDescription: "Proxies requests to Anthropic API with API key injection",
			},
			{
				Pattern:         "gateway/.*",
				Handler:         b.handleGatewayStreaming,
				HelpSynopsis:    "Anthropic Gateway proxy",
				HelpDescription: "Proxies requests to Anthropic API with API key injection",
			},
			// Transparent mode: role-based gateway paths
			{
				Pattern:         "role/[^/]+/gateway",
				Handler:         b.handleTransparentGatewayStreaming,
				HelpSynopsis:    "Anthropic Transparent Gateway proxy",
				HelpDescription: "Proxies requests to Anthropic API with implicit JWT authentication",
			},
			{
				Pattern:         "role/[^/]+/gateway/.*",
				Handler:         b.handleTransparentGatewayStreaming,
				HelpSynopsis:    "Anthropic Transparent Gateway proxy",
				HelpDescription: "Proxies requests to Anthropic API with implicit JWT authentication",
			},
		},
		ParseStreamBody: true, // Enable policy evaluation on model, max_tokens, etc.
		TransparentConfig: &framework.TransparentConfig{
			Enabled:      false,
			AutoAuthPath: "",
			DefaultAuthRole: "",
		},
		Backend: &framework.Backend{
			Help:           anthropicBackendHelp,
			BackendType:    "anthropic",
			BackendClass:   logical.ClassProvider,
			TokenExtractor: extractToken,
			Paths:          b.paths(),
		},
	}

	// Set common fields
	b.Logger = conf.Logger.WithSubsystem("anthropic")
	b.StorageView = conf.StorageView

	// Initialize reverse proxy with Anthropic transport
	b.StreamingBackend.InitProxy(sharedTransport)

	// Register transport shutdown hook for process-level cleanup
	if conf.RegisterShutdownHook != nil {
		conf.RegisterShutdownHook("anthropic-transport", ShutdownHTTPTransport)
	}

	if err := b.StreamingBackend.Setup(ctx, conf); err != nil {
		return nil, err
	}

	// Set defaults
	b.MaxBodySize = framework.DefaultMaxBodySize
	b.Timeout = DefaultAnthropicTimeout
	b.anthropicURL = DefaultAnthropicURL

	// Apply configuration if provided
	if len(conf.Config) > 0 {
		if err := ValidateConfig(conf.Config); err != nil {
			return nil, fmt.Errorf("invalid configuration: %w", err)
		}
		parsedConfig := parseConfig(conf.Config)
		b.anthropicURL = strings.TrimRight(parsedConfig.AnthropicURL, "/")
		b.MaxBodySize = parsedConfig.MaxBodySize
		b.Timeout = parsedConfig.Timeout

		b.StreamingBackend.SetTransparentConfig(&framework.TransparentConfig{
			Enabled:      parsedConfig.TransparentMode,
			AutoAuthPath: parsedConfig.AutoAuthPath,
			DefaultAuthRole: parsedConfig.DefaultAuthRole,
		})
	}

	return b, nil
}

// Initialize loads persisted config from storage
func (b *anthropicBackend) Initialize(ctx context.Context) error {
	if b.StorageView == nil {
		return nil
	}

	entry, err := b.StorageView.Get(ctx, "config")
	if err != nil {
		return fmt.Errorf("failed to read config from storage: %w", err)
	}
	if entry != nil {
		var config struct {
			AnthropicURL    string `json:"anthropic_url"`
			MaxBodySize     int64  `json:"max_body_size"`
			Timeout         string `json:"timeout"`
			TransparentMode bool   `json:"transparent_mode"`
			AutoAuthPath    string `json:"auto_auth_path"`
			DefaultAuthRole string `json:"default_role"`
		}
		if err := entry.DecodeJSON(&config); err != nil {
			return fmt.Errorf("failed to decode config: %w", err)
		}
		if config.AnthropicURL != "" {
			b.anthropicURL = strings.TrimRight(config.AnthropicURL, "/")
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
			DefaultAuthRole: config.DefaultAuthRole,
		})
	} else {
		// No persisted config — persist defaults
		tc := b.TransparentConfig
		defaultEntry, err := sdklogical.StorageEntryJSON("config", map[string]any{
			"anthropic_url":    b.anthropicURL,
			"max_body_size":    b.MaxBodySize,
			"timeout":          b.Timeout.String(),
			"transparent_mode": tc.Enabled,
			"auto_auth_path":   tc.AutoAuthPath,
			"default_role":     tc.DefaultAuthRole,
		})
		if err != nil {
			return fmt.Errorf("failed to create default config entry: %w", err)
		}
		if err := b.StorageView.Put(ctx, defaultEntry); err != nil {
			return fmt.Errorf("failed to persist default config: %w", err)
		}
		b.Logger.Info("persisted default configuration for new Anthropic provider")
	}
	return nil
}

// paths returns the configuration paths for the Anthropic provider
func (b *anthropicBackend) paths() []*framework.Path {
	return []*framework.Path{
		b.pathConfig(),
	}
}

// handleGatewayStreaming handles streaming gateway requests
func (b *anthropicBackend) handleGatewayStreaming(ctx context.Context, req *logical.Request, fd *framework.FieldData) error {
	b.handleGateway(ctx, req)
	return nil
}

// handleTransparentGatewayStreaming handles transparent mode gateway requests.
// The implicit auth has already been performed by the core request handler.
func (b *anthropicBackend) handleTransparentGatewayStreaming(ctx context.Context, req *logical.Request, fd *framework.FieldData) error {
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
func (b *anthropicBackend) SensitiveConfigFields() []string {
	return []string{}
}

const anthropicBackendHelp = `
The Anthropic provider enables proxying requests to the Anthropic API with
automatic credential management and API key injection.

Clients authenticate to Warden with a session token (via X-Warden-Token or
Authorization: Bearer header). The provider obtains an Anthropic API key from
the credential manager and injects it into the proxied request's x-api-key
header. This allows Warden to broker Anthropic access without exposing API
keys to clients.

The gateway path format is:
  /anthropic/gateway/{api-path}

Examples:
  /anthropic/gateway/v1/messages
  /anthropic/gateway/v1/models

Request body parsing is enabled, allowing policies to evaluate AI request
fields such as model, max_tokens, temperature, and stream. This enables
fine-grained cost control and usage policies.

Transparent mode allows implicit JWT authentication via role-based paths,
eliminating the need for clients to perform an explicit Warden login:
  /anthropic/role/{role}/gateway/{api-path}

The core extracts the role from the URL, performs implicit JWT auth against
the configured auth mount, and issues a short-lived token for the request.

Configuration:
- anthropic_url: Anthropic API base URL (default: https://api.anthropic.com)
- max_body_size: Maximum request body size (default: 10MB, max: 100MB)
- timeout: Request timeout duration (default: 120s for AI inference)
- transparent_mode: Enable implicit JWT authentication (default: false)
- auto_auth_path: JWT auth mount path for transparent mode (e.g., 'auth/jwt/')
- default_role: Fallback role when not specified in the URL path
`
