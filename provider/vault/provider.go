package vault

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logger"
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
	logger        *logger.GatedLogger
	proxy         *httputil.ReverseProxy
	vaultAddress  string
	maxBodySize   int64
	timeout       time.Duration
	tlsSkipVerify bool
	storageView   sdklogical.Storage
	cleanedUp     bool

	// Transparent mode fields
	transparentMode bool   // Enable transparent mode for implicit JWT authentication
	autoAuthPath    string // Path to JWT auth mount (e.g., "auth/jwt/")
	defaultRole     string // Default role when not specified in URL
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
	b := &vaultBackend{
		logger:      conf.Logger.WithSubsystem("vault"),
		storageView: conf.StorageView,
	}

	// Initialize proxy with empty director (we modify the request in handleGateway)
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

	// Apply configuration if provided
	if len(conf.Config) > 0 {
		parsedConfig := parseConfig(conf.Config)
		b.vaultAddress = parsedConfig.VaultAddress
		b.maxBodySize = parsedConfig.MaxBodySize
		b.timeout = parsedConfig.Timeout
		b.tlsSkipVerify = parsedConfig.TLSSkipVerify

		// Update transport if TLS skip verify is set
		if b.tlsSkipVerify {
			b.proxy.Transport = newVaultTransport(b.tlsSkipVerify)
		}
	}

	return b, nil
}

// Initialize loads persisted config from storage
func (b *vaultBackend) Initialize(ctx context.Context) error {
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
		b.maxBodySize = config.MaxBodySize
		b.tlsSkipVerify = config.TLSSkipVerify
		b.transparentMode = config.TransparentMode
		b.autoAuthPath = config.AutoAuthPath
		b.defaultRole = config.DefaultRole
		if config.Timeout != "" {
			if timeout, err := time.ParseDuration(config.Timeout); err == nil {
				b.timeout = timeout
			}
		}

		// Update transport if TLS skip verify is set
		if b.tlsSkipVerify {
			b.proxy.Transport = newVaultTransport(b.tlsSkipVerify)
		}

		// Sync transparent config with framework
		b.StreamingBackend.SetTransparentConfig(&framework.TransparentConfig{
			Enabled:      b.transparentMode,
			AutoAuthPath: b.autoAuthPath,
			DefaultRole:  b.defaultRole,
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
The Vault provider enables proxying requests to HashiCorp Vault with automatic
token injection.

Requests to the gateway/ path are proxied to Vault with the appropriate
Vault token injected from the credential manager.
`
