package gcp

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

// gcpBackend is the streaming backend for GCP provider operations
type gcpBackend struct {
	*framework.StreamingBackend
	tlsSkipVerify bool
	caData        string
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
			// Role-based gateway paths for implicit auth
			{
				Pattern:         "role/[^/]+/gateway",
				Handler:         b.handleTransparentGatewayStreaming,
				HelpSynopsis:    "GCP Transparent Gateway proxy",
				HelpDescription: "Proxies requests to Google Cloud APIs with role embedded in URL path",
			},
			{
				Pattern:         "role/[^/]+/gateway/.*",
				Handler:         b.handleTransparentGatewayStreaming,
				HelpSynopsis:    "GCP Transparent Gateway proxy",
				HelpDescription: "Proxies requests to Google Cloud APIs with role embedded in URL path",
			},
		},
		TransparentConfig: &framework.TransparentConfig{
			AutoAuthPath:    "",
			DefaultAuthRole: "",
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

	// Initialize reverse proxy with GCP transport (lazily created on first use)
	initTransport()
	b.StreamingBackend.InitProxy(sharedTransport)

	// Register transport shutdown hook for process-level cleanup
	if conf.RegisterShutdownHook != nil {
		conf.RegisterShutdownHook("gcp-transport", ShutdownHTTPTransport)
	}

	if err := b.StreamingBackend.Setup(ctx, conf); err != nil {
		return nil, err
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
		b.tlsSkipVerify = parsedConfig.TLSSkipVerify
		b.caData = parsedConfig.CAData

		if b.tlsSkipVerify || b.caData != "" {
			transport, err := newTransportWithTLS(b.caData, b.tlsSkipVerify)
			if err != nil {
				return nil, fmt.Errorf("invalid TLS configuration: %w", err)
			}
			b.Proxy.Transport = transport
		}

		b.StreamingBackend.SetTransparentConfig(&framework.TransparentConfig{
			AutoAuthPath:    parsedConfig.AutoAuthPath,
			DefaultAuthRole: parsedConfig.DefaultAuthRole,
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
			TLSSkipVerify   bool   `json:"tls_skip_verify"`
			CAData          string `json:"ca_data"`
			AutoAuthPath    string `json:"auto_auth_path"`
			DefaultAuthRole string `json:"default_role"`
		}
		if err := entry.DecodeJSON(&config); err != nil {
			return fmt.Errorf("failed to decode config: %w", err)
		}
		b.MaxBodySize = config.MaxBodySize
		b.tlsSkipVerify = config.TLSSkipVerify
		b.caData = config.CAData
		if config.Timeout != "" {
			if timeout, err := time.ParseDuration(config.Timeout); err == nil {
				b.Timeout = timeout
			}
		}

		if b.tlsSkipVerify || b.caData != "" {
			transport, err := newTransportWithTLS(b.caData, b.tlsSkipVerify)
			if err != nil {
				return fmt.Errorf("invalid TLS configuration: %w", err)
			}
			b.Proxy.Transport = transport
		}

		b.StreamingBackend.SetTransparentConfig(&framework.TransparentConfig{
			AutoAuthPath:    config.AutoAuthPath,
			DefaultAuthRole: config.DefaultAuthRole,
		})
	} else {
		// No persisted config — persist the defaults so a newly enabled
		// GCP provider is immediately configured and readable.
		tc := b.TransparentConfig
		defaultEntry, err := sdklogical.StorageEntryJSON("config", map[string]any{
			"max_body_size":   b.MaxBodySize,
			"timeout":         b.Timeout.String(),
			"tls_skip_verify": b.tlsSkipVerify,
			"ca_data":         b.caData,
			"auto_auth_path":  tc.AutoAuthPath,
			"default_role":    tc.DefaultAuthRole,
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

// handleTransparentGatewayStreaming handles gateway requests with implicit auth.
// The implicit auth has already been performed by the core request handler.
// This method rewrites the path and delegates to the standard gateway handler.
func (b *gcpBackend) handleTransparentGatewayStreaming(ctx context.Context, req *logical.Request, fd *framework.FieldData) error {
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
	if err := framework.ValidateAllowedKeys(config,
		"max_body_size", "timeout", "tls_skip_verify", "ca_data",
		"auto_auth_path", "default_role"); err != nil {
		return err
	}
	if err := framework.ValidateCommonConfig(config); err != nil {
		return err
	}
	return framework.ValidateTLSConfig(config)
}

// SensitiveConfigFields returns the list of config fields that should be masked in output
func (b *gcpBackend) SensitiveConfigFields() []string {
	return []string{"ca_data"}
}

const gcpBackendHelp = `
The GCP provider enables proxying requests to Google Cloud APIs with automatic
credential management and Bearer token injection.

Warden performs implicit authentication on every request and obtains a GCP
OAuth2 access token from the credential manager — minted by exchanging the
source's service account key, or by impersonating a target service account
via the IAM Credentials API — and injects it into the proxied request's
Authorization header. This allows Warden to broker Google Cloud access
without exposing service account keys to clients.

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

The role can be provided via the X-Warden-Role header, or embedded in
the URL path:
  /gcp/role/{role}/gateway/{googleapis-host}/{path}

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
- auto_auth_path: Auth mount path for implicit authentication (e.g., 'auth/jwt/')
- default_role: Fallback role when not specified in the URL path
`
