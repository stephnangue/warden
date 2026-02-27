package vault

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

// vaultUnauthenticatedPaths are read-only Vault endpoints that can be accessed
// without authentication in transparent mode. These are PKI certificate endpoints
// that the Terraform Vault provider accesses without sending tokens.
var vaultUnauthenticatedPaths = []string{
	// PKI issuer endpoints (read-only certificate data)
	"v1/+/issuer/+/pem",     // /v1/{mount}/issuer/{id}/pem
	"v1/+/issuer/+/der",     // /v1/{mount}/issuer/{id}/der
	"v1/+/issuer/+/json",    // /v1/{mount}/issuer/{id}/json
	"v1/+/issuer/+/crl",     // /v1/{mount}/issuer/{id}/crl
	"v1/+/issuer/+/crl/pem", // /v1/{mount}/issuer/{id}/crl/pem
	"v1/+/issuer/+/crl/der", // /v1/{mount}/issuer/{id}/crl/der
	// PKI CA endpoints
	"v1/+/ca/pem",        // /v1/{mount}/ca/pem
	"v1/+/ca",            // /v1/{mount}/ca (DER format)
	"v1/+/ca_chain",      // /v1/{mount}/ca_chain
	"v1/+/cert/ca",       // /v1/{mount}/cert/ca
	"v1/+/cert/ca_chain", // /v1/{mount}/cert/ca_chain
	// PKI CRL endpoints
	"v1/+/cert/crl",      // /v1/{mount}/cert/crl
	"v1/+/crl",           // /v1/{mount}/crl (DER format)
	"v1/+/crl/pem",       // /v1/{mount}/crl/pem
	"v1/+/crl/der",       // /v1/{mount}/crl/der
	"v1/+/crl/delta",     // /v1/{mount}/crl/delta
	"v1/+/crl/delta/pem", // /v1/{mount}/crl/delta/pem
	// PKI certificate list/read endpoints
	"v1/+/certs",  // /v1/{mount}/certs (list serial numbers)
	"v1/+/cert/+", // /v1/{mount}/cert/{serial}
}

// vaultBackend is the streaming backend for Vault provider operations
type vaultBackend struct {
	*framework.StreamingBackend
	vaultAddress  string
	tlsSkipVerify bool
}

// extractToken extracts Warden token from X-Vault-Token header or Authorization: Bearer
func extractToken(r *http.Request) string {
	// Primary: X-Vault-Token header (standard Vault header)
	if token := r.Header.Get("X-Vault-Token"); token != "" {
		return token
	}
	// Fallback: Authorization: Bearer
	authHeader := r.Header.Get("Authorization")
	if len(authHeader) > 7 && strings.EqualFold(authHeader[:7], "Bearer ") {
		return authHeader[7:]
	}
	return ""
}

// Factory creates a new Vault provider backend using the logical.Factory pattern
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &vaultBackend{}

	// Create the streaming backend with gateway path for streaming
	b.StreamingBackend = &framework.StreamingBackend{
		StreamingPaths: []*framework.StreamingPath{
			{
				Pattern:         "gateway",
				Handler:         b.handleGatewayStreaming,
				HelpSynopsis:    "Vault Gateway proxy",
				HelpDescription: "Proxies requests to HashiCorp Vault with token injection",
			},
			{
				Pattern:         "gateway/.*",
				Handler:         b.handleGatewayStreaming,
				HelpSynopsis:    "Vault Gateway proxy",
				HelpDescription: "Proxies requests to HashiCorp Vault with token injection",
			},
			// Transparent mode: role-based gateway paths
			{
				Pattern:         "role/[^/]+/gateway",
				Handler:         b.handleTransparentGatewayStreaming,
				HelpSynopsis:    "Vault Transparent Gateway proxy",
				HelpDescription: "Proxies requests to HashiCorp Vault with implicit JWT authentication",
			},
			{
				Pattern:         "role/[^/]+/gateway/.*",
				Handler:         b.handleTransparentGatewayStreaming,
				HelpSynopsis:    "Vault Transparent Gateway proxy",
				HelpDescription: "Proxies requests to HashiCorp Vault with implicit JWT authentication",
			},
		},
		UnauthenticatedPaths: vaultUnauthenticatedPaths,
		ParseStreamBody:      true,
		TransparentConfig: &framework.TransparentConfig{
			Enabled:      false, // Updated via config write or Initialize
			AutoAuthPath: "",
			DefaultRole:  "",
		},
		Backend: &framework.Backend{
			Help:           vaultBackendHelp,
			BackendType:    "vault",
			BackendClass:   logical.ClassProvider,
			TokenExtractor: extractToken,
			Paths:          b.paths(),
		},
	}

	// Set common fields
	b.Logger = conf.Logger.WithSubsystem("vault")
	b.StorageView = conf.StorageView

	// Initialize reverse proxy with Vault transport
	b.StreamingBackend.InitProxy(sharedTransport)

	// Register transport shutdown hook for process-level cleanup
	if conf.RegisterShutdownHook != nil {
		conf.RegisterShutdownHook("vault-transport", ShutdownHTTPTransport)
	}

	// Set defaults
	b.MaxBodySize = framework.DefaultMaxBodySize
	b.Timeout = framework.DefaultTimeout

	// Apply configuration if provided
	if len(conf.Config) > 0 {
		parsedConfig := parseConfig(conf.Config)
		b.vaultAddress = parsedConfig.VaultAddress
		b.MaxBodySize = parsedConfig.MaxBodySize
		b.Timeout = parsedConfig.Timeout
		b.tlsSkipVerify = parsedConfig.TLSSkipVerify

		// Update transport if TLS skip verify is set
		if b.tlsSkipVerify {
			b.Proxy.Transport = newVaultTransport(b.tlsSkipVerify)
		}
	}

	return b, nil
}

// Initialize loads persisted config from storage
func (b *vaultBackend) Initialize(ctx context.Context) error {
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
			VaultAddress    string `json:"vault_address"`
			MaxBodySize     int64  `json:"max_body_size"`
			Timeout         string `json:"timeout"`
			TLSSkipVerify   bool   `json:"tls_skip_verify"`
			TransparentMode bool   `json:"transparent_mode"`
			AutoAuthPath    string `json:"auto_auth_path"`
			DefaultRole     string `json:"default_role"`
		}
		if err := entry.DecodeJSON(&config); err != nil {
			return fmt.Errorf("failed to decode config: %w", err)
		}
		b.vaultAddress = config.VaultAddress
		b.MaxBodySize = config.MaxBodySize
		b.tlsSkipVerify = config.TLSSkipVerify
		if config.Timeout != "" {
			if timeout, err := time.ParseDuration(config.Timeout); err == nil {
				b.Timeout = timeout
			}
		}

		// Update transport if TLS skip verify is set
		if b.tlsSkipVerify {
			b.Proxy.Transport = newVaultTransport(b.tlsSkipVerify)
		}

		b.StreamingBackend.SetTransparentConfig(&framework.TransparentConfig{
			Enabled:      config.TransparentMode,
			AutoAuthPath: config.AutoAuthPath,
			DefaultRole:  config.DefaultRole,
		})
	}
	return nil
}

// paths returns the configuration paths for the Vault provider
func (b *vaultBackend) paths() []*framework.Path {
	return []*framework.Path{
		b.pathConfig(),
	}
}

// handleGatewayStreaming handles streaming gateway requests
func (b *vaultBackend) handleGatewayStreaming(ctx context.Context, req *logical.Request, fd *framework.FieldData) error {
	b.handleGateway(ctx, req)
	return nil
}

// handleTransparentGatewayStreaming handles transparent mode gateway requests.
// The implicit auth has already been performed by the core request handler.
// This method rewrites the path and delegates to the standard gateway handler.
func (b *vaultBackend) handleTransparentGatewayStreaming(ctx context.Context, req *logical.Request, fd *framework.FieldData) error {
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

// SensitiveConfigFields returns the list of config fields that should be masked in output
func (b *vaultBackend) SensitiveConfigFields() []string {
	// Vault provider doesn't store credentials in config - uses credential minting from specs
	return []string{}
}

const vaultBackendHelp = `
The Vault provider enables proxying requests to HashiCorp Vault (or OpenBao)
with automatic credential management and Vault token injection.

Clients authenticate to Warden with a session token (via X-Vault-Token or
Authorization: Bearer header). The provider obtains a Vault token from the
credential manager — generated by a Vault source driver using the configured
auth method and role — and injects it as the X-Vault-Token header in the
proxied request. This allows Warden to broker Vault access without distributing
long-lived Vault tokens to clients.

Like GitLab, the Vault provider targets a single instance configured via
vault_address. The gateway automatically prepends /v1 to API paths when not
already present, matching Vault's standard API prefix.

The gateway path format is:
  /vault/gateway/{vault-api-path}

The {vault-api-path} maps to the Vault REST API. If the path does not begin
with /v1/, the provider prepends it automatically.

Examples:
  /vault/gateway/secret/data/my-secret        → /v1/secret/data/my-secret
  /vault/gateway/v1/secret/data/my-secret     → /v1/secret/data/my-secret
  /vault/gateway/auth/token/lookup-self        → /v1/auth/token/lookup-self
  /vault/gateway/pki/issue/my-role             → /v1/pki/issue/my-role
  /vault/gateway/database/creds/my-role        → /v1/database/creds/my-role
  /vault/gateway/sys/health                    → /v1/sys/health

Transparent mode allows implicit JWT authentication via role-based paths,
eliminating the need for clients to perform an explicit Warden login:
  /vault/role/{role}/gateway/{vault-api-path}

The core extracts the role from the URL, performs implicit JWT auth against
the configured auth mount, and issues a short-lived token for the request.

Unauthenticated paths: Certain read-only PKI endpoints (CA certificates,
CRLs, issuer data) are forwarded without authentication, matching Vault's
own unauthenticated access policy. This enables tools like Terraform to
fetch CA chains without requiring a Warden session.

Configuration:
- vault_address: Base URL of the Vault instance (required, e.g., "https://vault.example.com:8200")
- tls_skip_verify: Skip TLS certificate verification (default: false, use only for development)
- max_body_size: Maximum request body size (default: 10MB, max: 100MB)
- timeout: Request timeout duration (e.g., '30s', '5m')
- transparent_mode: Enable implicit JWT authentication (default: false)
- auto_auth_path: JWT auth mount path for transparent mode (e.g., 'auth/jwt/')
- default_role: Fallback role when not specified in the URL path
`
