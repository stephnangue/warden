package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

// gcpBackend is the streaming backend for GCP provider operations
type gcpBackend struct {
	*framework.StreamingBackend
}

// extractToken extracts Warden token from Authorization Bearer header or X-Warden-Token header
func extractToken(r *http.Request) string {
	// First, check X-Warden-Token header (explicit Warden token)
	if token := r.Header.Get("X-Warden-Token"); token != "" {
		return token
	}

	// Then check Authorization header for Bearer token
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}

	return ""
}

// Factory creates a new GCP provider backend using the logical.Factory pattern
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &gcpBackend{}

	// Create the streaming backend with gateway path for streaming
	b.StreamingBackend = &framework.StreamingBackend{
		StreamingPaths: []*framework.StreamingPath{
			{
				Pattern:         "gateway",
				Handler:         b.handleGatewayStreaming,
				HelpSynopsis:    "GCP Gateway proxy",
				HelpDescription: "Proxies requests to Google Cloud APIs with Bearer token injection",
			},
			{
				Pattern:         "gateway/.*",
				Handler:         b.handleGatewayStreaming,
				HelpSynopsis:    "GCP Gateway proxy",
				HelpDescription: "Proxies requests to Google Cloud APIs with Bearer token injection",
			},
			// Transparent mode: role-based gateway paths
			{
				Pattern:         "role/[^/]+/gateway",
				Handler:         b.handleTransparentGatewayStreaming,
				HelpSynopsis:    "GCP Transparent Gateway proxy",
				HelpDescription: "Proxies requests to Google Cloud APIs with implicit JWT authentication",
			},
			{
				Pattern:         "role/[^/]+/gateway/.*",
				Handler:         b.handleTransparentGatewayStreaming,
				HelpSynopsis:    "GCP Transparent Gateway proxy",
				HelpDescription: "Proxies requests to Google Cloud APIs with implicit JWT authentication",
			},
		},
		TransparentConfig: &framework.TransparentConfig{
			Enabled:      false, // Updated via config write or Initialize
			AutoAuthPath: "",
			DefaultRole:  "",
		},
		Backend: &framework.Backend{
			Help:           gcpBackendHelp,
			BackendType:    "gcp",
			BackendClass:   logical.ClassProvider,
			TokenExtractor: extractToken,
			Paths:          b.paths(),
		},
	}

	// Set common fields
	b.Logger = conf.Logger.WithSubsystem("gcp")
	b.StorageView = conf.StorageView

	// Initialize reverse proxy with GCP transport
	b.StreamingBackend.InitProxy(sharedTransport)

	// Register transport shutdown hook for process-level cleanup
	if conf.RegisterShutdownHook != nil {
		conf.RegisterShutdownHook("gcp-transport", ShutdownHTTPTransport)
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
func (b *gcpBackend) Initialize(ctx context.Context) error {
	if b.StorageView == nil {
		return nil
	}

	// Load persisted config from storage
	entry, err := b.StorageView.Get(ctx, "config")
	if err != nil {
		return fmt.Errorf("failed to read config from storage: %w", err)
	}
	if entry != nil {
		var config struct {
			MaxBodySize     int64  `json:"max_body_size"`
			Timeout         string `json:"timeout"`
			TransparentMode bool   `json:"transparent_mode"`
			AutoAuthPath    string `json:"auto_auth_path"`
			DefaultRole     string `json:"default_role"`
		}
		if err := entry.DecodeJSON(&config); err != nil {
			return fmt.Errorf("failed to decode config: %w", err)
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
		// No persisted config — persist the defaults so a newly enabled
		// GCP provider is immediately configured and readable.
		tc := b.TransparentConfig
		defaultEntry, err := sdklogical.StorageEntryJSON("config", map[string]any{
			"max_body_size":    b.MaxBodySize,
			"timeout":          b.Timeout.String(),
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
		b.Logger.Info("persisted default configuration for new GCP provider")
	}
	return nil
}

// paths returns the configuration paths for the GCP provider
func (b *gcpBackend) paths() []*framework.Path {
	return []*framework.Path{
		b.pathConfig(),
	}
}

// handleGatewayStreaming handles streaming gateway requests
func (b *gcpBackend) handleGatewayStreaming(ctx context.Context, req *logical.Request, fd *framework.FieldData) error {
	b.handleGateway(ctx, req)
	return nil
}

// handleTransparentGatewayStreaming handles transparent mode gateway requests.
// The implicit auth has already been performed by the core request handler.
// This method rewrites the path and delegates to the standard gateway handler.
func (b *gcpBackend) handleTransparentGatewayStreaming(ctx context.Context, req *logical.Request, fd *framework.FieldData) error {
	if !b.StreamingBackend.IsTransparentMode() {
		http.Error(req.ResponseWriter, "Transparent mode not enabled", http.StatusForbidden)
		return nil
	}

	// Rewrite the path: /role/{role}/gateway/... -> /gateway/...
	// The original path in req.Path is relative to the mount point
	req.Path = b.StreamingBackend.RewriteTransparentPath(req.Path)

	// Also update the HTTP request URL path for the proxy
	if req.HTTPRequest != nil && req.HTTPRequest.URL != nil {
		req.HTTPRequest.URL.Path = b.StreamingBackend.RewriteTransparentPath(req.HTTPRequest.URL.Path)
	}

	// Delegate to standard gateway handler
	b.handleGateway(ctx, req)
	return nil
}

// ValidateConfig validates GCP provider-specific configuration
func ValidateConfig(config map[string]any) error {
	allowedKeys := map[string]bool{
		"max_body_size":    true,
		"timeout":          true,
		"transparent_mode": true,
		"auto_auth_path":   true,
		"default_role":     true,
	}

	// Check for unknown keys
	for key := range config {
		if !allowedKeys[key] {
			return fmt.Errorf("unknown configuration key: %s (allowed: max_body_size, timeout, transparent_mode, auto_auth_path, default_role)", key)
		}
	}

	// Validate max_body_size
	if maxSize, ok := config["max_body_size"]; ok {
		var size int64
		switch v := maxSize.(type) {
		case int:
			size = int64(v)
		case int64:
			size = v
		case float64:
			size = int64(v)
		case json.Number:
			parsed, err := v.Int64()
			if err != nil {
				return fmt.Errorf("max_body_size must be an integer, got json.Number that can't be parsed: %w", err)
			}
			size = parsed
		case string:
			parsed, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return fmt.Errorf("max_body_size must be an integer, got string that can't be parsed: %w", err)
			}
			size = parsed
		default:
			return fmt.Errorf("max_body_size must be an integer, got %T", maxSize)
		}
		if size < 0 {
			return fmt.Errorf("max_body_size must be greater than 0")
		}
		if size > 104857600 { // 100MB
			return fmt.Errorf("max_body_size must not exceed 104857600 bytes (100MB)")
		}
	}

	// Validate timeout
	if timeout, ok := config["timeout"]; ok {
		switch v := timeout.(type) {
		case string:
			if _, err := time.ParseDuration(v); err != nil {
				return fmt.Errorf("invalid timeout format: %w (expected format: '30s', '5m', '1h')", err)
			}
		case int:
			if v < 0 {
				return fmt.Errorf("timeout must be greater than 0 seconds")
			}
		case float64:
			if v < 0 {
				return fmt.Errorf("timeout must be greater than 0 seconds")
			}
		default:
			return fmt.Errorf("timeout must be a duration string (e.g., '30s') or integer (seconds)")
		}
	}

	// Validate transparent_mode
	if tm, ok := config["transparent_mode"]; ok {
		switch tm.(type) {
		case bool:
			// valid
		default:
			return fmt.Errorf("transparent_mode must be a boolean")
		}
	}

	// Validate auto_auth_path
	if aap, ok := config["auto_auth_path"]; ok {
		if _, ok := aap.(string); !ok {
			return fmt.Errorf("auto_auth_path must be a string")
		}
	}

	// Validate default_role
	if dr, ok := config["default_role"]; ok {
		if _, ok := dr.(string); !ok {
			return fmt.Errorf("default_role must be a string")
		}
	}

	return nil
}

// SensitiveConfigFields returns the list of config fields that should be masked in output
func (b *gcpBackend) SensitiveConfigFields() []string {
	// GCP provider doesn't store credentials in config - uses credential minting from specs
	return []string{}
}

const gcpBackendHelp = `
The GCP provider enables proxying requests to Google Cloud APIs with automatic
credential management and Bearer token injection.

Clients authenticate to Warden with a session token (via X-Warden-Token or
Authorization: Bearer header). The provider obtains a GCP OAuth2 access token
from the credential manager — minted by exchanging the source's service account
key, or by impersonating a target service account via the IAM Credentials API —
and injects it into the proxied request's Authorization header. This allows
Warden to broker Google Cloud access without exposing service account keys to
clients.

The gateway path format is:
  /gcp/gateway/{googleapis-host}/{path}

The {googleapis-host} segment determines which Google Cloud API receives the
request. Any *.googleapis.com hostname is accepted; the provider proxies to
it over HTTPS.

Examples:
  /gcp/gateway/storage.googleapis.com/storage/v1/b/my-bucket
  /gcp/gateway/compute.googleapis.com/compute/v1/projects/my-project/zones
  /gcp/gateway/secretmanager.googleapis.com/v1/projects/my-project/secrets
  /gcp/gateway/container.googleapis.com/v1/projects/my-project/locations/-/clusters
  /gcp/gateway/bigquery.googleapis.com/bigquery/v2/projects/my-project/datasets

Transparent mode allows implicit JWT authentication via role-based paths,
eliminating the need for clients to perform an explicit Warden login:
  /gcp/role/{role}/gateway/{googleapis-host}/{path}

The core extracts the role from the URL, performs implicit JWT auth against
the configured auth mount, and issues a short-lived token for the request.

Supported Google Cloud APIs (non-exhaustive):
- Cloud Storage (storage.googleapis.com)
- Compute Engine (compute.googleapis.com)
- BigQuery (bigquery.googleapis.com)
- Cloud Resource Manager (cloudresourcemanager.googleapis.com)
- IAM (iam.googleapis.com)
- Secret Manager (secretmanager.googleapis.com)
- Container Engine (container.googleapis.com)
- Any other *.googleapis.com endpoint

Credential mint methods:
- access_token: Exchange source SA key for an OAuth2 token (default)
- impersonated_access_token: Impersonate a target SA via IAM Credentials API

Configuration:
- max_body_size: Maximum request body size (default: 10MB, max: 100MB)
- timeout: Request timeout duration (e.g., '30s', '5m')
- transparent_mode: Enable implicit JWT authentication (default: false)
- auto_auth_path: JWT auth mount path for transparent mode (e.g., 'auth/jwt/')
- default_role: Fallback role when not specified in the URL path
`
