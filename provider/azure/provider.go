package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// azureBackend is the streaming backend for Azure provider operations
type azureBackend struct {
	*framework.StreamingBackend
	logger      *logger.GatedLogger
	proxy       *httputil.ReverseProxy
	allowedHosts []string // Allowed Azure hosts for proxying
	maxBodySize  int64
	timeout      time.Duration
	storageView  sdklogical.Storage

	// Transparent mode fields
	transparentMode bool   // Enable transparent mode for implicit JWT authentication
	autoAuthPath    string // Path to JWT auth mount (e.g., "auth/jwt/")
	defaultRole     string // Default role when not specified in URL
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

// Factory creates a new Azure provider backend using the logical.Factory pattern
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &azureBackend{
		logger:      conf.Logger.WithSubsystem("azure"),
		storageView: conf.StorageView,
	}

	// Initialize reverse proxy
	b.proxy = &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			// Request is already prepared by handleGateway - nothing to do here
		},
		Transport: sharedTransport,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			b.logger.Error("proxy error",
				logger.Err(err),
				logger.String("target_url", r.URL.String()),
			)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
	}

	// Create the streaming backend with gateway path for streaming
	b.StreamingBackend = &framework.StreamingBackend{
		StreamingPaths: []*framework.StreamingPath{
			{
				Pattern:         "gateway",
				Handler:         b.handleGatewayStreaming,
				HelpSynopsis:    "Azure Gateway proxy",
				HelpDescription: "Proxies requests to Azure services with Bearer token injection",
			},
			{
				Pattern:         "gateway/.*",
				Handler:         b.handleGatewayStreaming,
				HelpSynopsis:    "Azure Gateway proxy",
				HelpDescription: "Proxies requests to Azure services with Bearer token injection",
			},
			// Transparent mode: role-based gateway paths
			{
				Pattern:         "role/[^/]+/gateway",
				Handler:         b.handleTransparentGatewayStreaming,
				HelpSynopsis:    "Azure Transparent Gateway proxy",
				HelpDescription: "Proxies requests to Azure services with implicit JWT authentication",
			},
			{
				Pattern:         "role/[^/]+/gateway/.*",
				Handler:         b.handleTransparentGatewayStreaming,
				HelpSynopsis:    "Azure Transparent Gateway proxy",
				HelpDescription: "Proxies requests to Azure services with implicit JWT authentication",
			},
		},
		TransparentConfig: &framework.TransparentConfig{
			Enabled:      false, // Updated via config write or Initialize
			AutoAuthPath: "",
			DefaultRole:  "",
		},
		Backend: &framework.Backend{
			Help:           azureBackendHelp,
			BackendType:    "azure",
			BackendClass:   logical.ClassProvider,
			TokenExtractor: extractToken,
			Paths:          b.paths(),
		},
	}

	// Register transport shutdown hook for process-level cleanup
	if conf.RegisterShutdownHook != nil {
		conf.RegisterShutdownHook("azure-transport", ShutdownHTTPTransport)
	}

	// Set defaults
	b.allowedHosts = DefaultAllowedHosts
	b.maxBodySize = DefaultMaxBodySize
	b.timeout = DefaultTimeout

	// Apply configuration if provided
	if len(conf.Config) > 0 {
		if err := ValidateConfig(conf.Config); err != nil {
			return nil, fmt.Errorf("invalid configuration: %w", err)
		}
		parsedConfig := parseConfig(conf.Config)
		b.allowedHosts = parsedConfig.AllowedHosts
		b.maxBodySize = parsedConfig.MaxBodySize
		b.timeout = parsedConfig.Timeout
		b.transparentMode = parsedConfig.TransparentMode
		b.autoAuthPath = parsedConfig.AutoAuthPath
		b.defaultRole = parsedConfig.DefaultRole

		// Sync transparent config with framework
		b.StreamingBackend.SetTransparentConfig(&framework.TransparentConfig{
			Enabled:      b.transparentMode,
			AutoAuthPath: b.autoAuthPath,
			DefaultRole:  b.defaultRole,
		})
	}

	return b, nil
}

// Initialize loads persisted config from storage
func (b *azureBackend) Initialize(ctx context.Context) error {
	if b.storageView == nil {
		return nil
	}

	// Load persisted config from storage
	entry, err := b.storageView.Get(ctx, "config")
	if err != nil {
		return fmt.Errorf("failed to read config from storage: %w", err)
	}
	if entry != nil {
		var config struct {
			AllowedHosts    []string `json:"allowed_hosts"`
			MaxBodySize     int64    `json:"max_body_size"`
			Timeout         string   `json:"timeout"`
			TransparentMode bool     `json:"transparent_mode"`
			AutoAuthPath    string   `json:"auto_auth_path"`
			DefaultRole     string   `json:"default_role"`
		}
		if err := entry.DecodeJSON(&config); err != nil {
			return fmt.Errorf("failed to decode config: %w", err)
		}
		b.allowedHosts = config.AllowedHosts
		b.maxBodySize = config.MaxBodySize
		b.transparentMode = config.TransparentMode
		b.autoAuthPath = config.AutoAuthPath
		b.defaultRole = config.DefaultRole
		if config.Timeout != "" {
			if timeout, err := time.ParseDuration(config.Timeout); err == nil {
				b.timeout = timeout
			}
		}

		// Sync transparent config with framework
		b.StreamingBackend.SetTransparentConfig(&framework.TransparentConfig{
			Enabled:      b.transparentMode,
			AutoAuthPath: b.autoAuthPath,
			DefaultRole:  b.defaultRole,
		})
	} else {
		// No persisted config — persist the defaults so a newly enabled
		// Azure provider is immediately configured and readable.
		defaultEntry, err := sdklogical.StorageEntryJSON("config", map[string]any{
			"allowed_hosts":    b.allowedHosts,
			"max_body_size":    b.maxBodySize,
			"timeout":          b.timeout.String(),
			"transparent_mode": b.transparentMode,
			"auto_auth_path":   b.autoAuthPath,
			"default_role":     b.defaultRole,
		})
		if err != nil {
			return fmt.Errorf("failed to create default config entry: %w", err)
		}
		if err := b.storageView.Put(ctx, defaultEntry); err != nil {
			return fmt.Errorf("failed to persist default config: %w", err)
		}
		b.logger.Info("persisted default configuration for new Azure provider")
	}
	return nil
}

// paths returns the configuration paths for the Azure provider
func (b *azureBackend) paths() []*framework.Path {
	return []*framework.Path{
		b.pathConfig(),
	}
}

// handleGatewayStreaming handles streaming gateway requests
func (b *azureBackend) handleGatewayStreaming(ctx context.Context, req *logical.Request, fd *framework.FieldData) error {
	b.handleGateway(ctx, req)
	return nil
}

// handleTransparentGatewayStreaming handles transparent mode gateway requests.
// The implicit auth has already been performed by the core request handler.
// This method rewrites the path and delegates to the standard gateway handler.
func (b *azureBackend) handleTransparentGatewayStreaming(ctx context.Context, req *logical.Request, fd *framework.FieldData) error {
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

// ValidateConfig validates Azure provider-specific configuration
func ValidateConfig(config map[string]any) error {
	allowedKeys := map[string]bool{
		"allowed_hosts":    true,
		"max_body_size":    true,
		"timeout":          true,
		"transparent_mode": true,
		"auto_auth_path":   true,
		"default_role":     true,
	}

	// Check for unknown keys
	for key := range config {
		if !allowedKeys[key] {
			return fmt.Errorf("unknown configuration key: %s (allowed: allowed_hosts, max_body_size, timeout, transparent_mode, auto_auth_path, default_role)", key)
		}
	}

	// Validate allowed_hosts
	if hosts, ok := config["allowed_hosts"]; ok {
		switch v := hosts.(type) {
		case []any:
			for i, h := range v {
				if _, ok := h.(string); !ok {
					return fmt.Errorf("allowed_hosts[%d] must be a string", i)
				}
			}
		case []string:
		default:
			return fmt.Errorf("allowed_hosts must be an array of strings")
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
func (b *azureBackend) SensitiveConfigFields() []string {
	// Azure provider doesn't store credentials in config - uses credential minting from specs
	return []string{}
}

const azureBackendHelp = `
The Azure provider enables proxying requests to Azure services with automatic
credential management and Bearer token injection.

Requests to the gateway/ path are proxied to Azure with the appropriate
Bearer token injected into the Authorization header.

The gateway path format is:
  /azure/gateway/{azure-host}/{path}

Examples:
  /azure/gateway/management.azure.com/subscriptions?api-version=2022-12-01
  /azure/gateway/myvault.vault.azure.net/secrets/mysecret?api-version=7.4
  /azure/gateway/mystorage.blob.core.windows.net/container/blob

Transparent mode allows implicit JWT authentication via role-based paths:
  /azure/role/{role}/gateway/{azure-host}/{path}

Supported Azure services:
- Azure Resource Manager (management.azure.com)
- Azure Key Vault (*.vault.azure.net)
- Azure Storage (*.blob.core.windows.net, *.queue.core.windows.net, etc.)
- Microsoft Graph (graph.microsoft.com)
`
