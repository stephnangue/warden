package azure

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// azureBackend is the streaming backend for Azure provider operations
type azureBackend struct {
	*framework.StreamingBackend

	// mu guards the TLS settings and the host allowlist, which a config
	// write replaces while a config read or a gateway request reads them.
	mu            sync.RWMutex
	tlsSkipVerify bool
	caData        string
	allowedHosts  []string

	// configWriteMu serializes config writes, so each one validates, persists
	// and applies against the configuration the previous one left.
	configWriteMu sync.Mutex
}

// tlsSettings is the TLS configuration of the transport to Azure.
func (b *azureBackend) tlsSettings() (skipVerify bool, caData string) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.tlsSkipVerify, b.caData
}

// setTLSSettings replaces the TLS settings.
func (b *azureBackend) setTLSSettings(skipVerify bool, caData string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.tlsSkipVerify, b.caData = skipVerify, caData
}

// defaultAllowedHostSuffixes are the hosts an Azure mount forwards to when
// the operator names none: Microsoft-run API endpoints of the public cloud.
// Each is named where it starts, not by a broad suffix: azure.com also holds
// hosts customers control, such as a VM's <label>.<region>.cloudapp.azure.com,
// and a request leaves carrying an Entra token.
var defaultAllowedHostSuffixes = []string{
	".management.azure.com",        // Resource Manager
	".graph.microsoft.com",         // Microsoft Graph
	".vault.azure.net",             // Key Vault
	".blob.core.windows.net",       // Blob Storage
	".queue.core.windows.net",      // Queue Storage
	".table.core.windows.net",      // Table Storage
	".file.core.windows.net",       // File Storage
	".dfs.core.windows.net",        // Data Lake Storage
	".openai.azure.com",            // Azure OpenAI
	".cognitiveservices.azure.com", // Azure AI services
	".services.ai.azure.com",       // Azure AI Foundry
}

// hostAllowlist is the allowlist of target hosts in force: the operator's, or
// the default when the operator named none. The slice is replaced, never
// changed in place, so a caller may read it after the lock is released.
func (b *azureBackend) hostAllowlist() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if len(b.allowedHosts) == 0 {
		return defaultAllowedHostSuffixes
	}
	return b.allowedHosts
}

// configuredHostAllowlist is the operator's allowlist, nil when they named
// none. It is what is persisted, so a mount on the default follows it.
func (b *azureBackend) configuredHostAllowlist() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.allowedHosts
}

// setHostAllowlist replaces the operator's allowlist; an empty one restores
// the default.
func (b *azureBackend) setHostAllowlist(allowlist []string) {
	if len(allowlist) == 0 {
		allowlist = nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.allowedHosts = allowlist
}

// extractTokens resolves the two principals on an Azure gateway request.
//
// The only agent channel is X-Warden-Token. On a protected-resource mount an
// agent presented out of band — X-Warden-Agent-Token or a trusted client
// certificate — frees Authorization to carry the user.
//
// Extraction matrix. "-" means nothing extracted; an empty agent under a
// client certificate means the certificate authenticates the agent
// downstream. Off the user leg there is never a user.
//
//	request carries                     agent(off)  agent(on)  user(on)
//	Authorization: Bearer u             u           u          -
//	X-Warden-Token: w + Bearer u        w           w          -
//	X-Warden-Agent-Token: a + Bearer u  u           a          u
//	client cert + Bearer u              u           -          u
//	client cert only                    -           -          -
func extractTokens(r *http.Request, userLeg bool) (agent, user string) {
	return logical.ExtractTokensWithChannels(r, userLeg, "X-Warden-Token")
}

// Factory creates a new Azure provider backend using the logical.Factory pattern
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &azureBackend{}

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
			// Role-based gateway paths for implicit auth
			{
				Pattern:         "role/[^/]+/gateway",
				Handler:         b.handleTransparentGatewayStreaming,
				HelpSynopsis:    "Azure Transparent Gateway proxy",
				HelpDescription: "Proxies requests to Azure services with role embedded in URL path",
			},
			{
				Pattern:         "role/[^/]+/gateway/.*",
				Handler:         b.handleTransparentGatewayStreaming,
				HelpSynopsis:    "Azure Transparent Gateway proxy",
				HelpDescription: "Proxies requests to Azure services with role embedded in URL path",
			},
		},
		Backend: &framework.Backend{
			Help:           azureBackendHelp,
			BackendType:    "azure",
			BackendClass:   logical.ClassProvider,
			TokenExtractor: extractTokens,
			Paths:          b.paths(),
		},
	}

	// Set common fields
	b.Logger = conf.Logger.WithSubsystem("azure")
	b.StorageView = conf.StorageView

	// Seed an empty transparent config so isTransparentRequest can route
	// once auto_auth_path is configured via handleConfigWrite.
	b.StreamingBackend.SetTransparentConfig(&framework.TransparentConfig{})

	// Initialize reverse proxy with Azure transport (lazily created on first use)
	initTransport()
	b.StreamingBackend.InitProxy(sharedTransport)

	// Register transport shutdown hook for process-level cleanup
	if conf.RegisterShutdownHook != nil {
		conf.RegisterShutdownHook("azure-transport", ShutdownHTTPTransport)
	}

	if err := b.StreamingBackend.Setup(ctx, conf); err != nil {
		return nil, err
	}

	// Set defaults
	b.SetMaxBodySize(framework.DefaultMaxBodySize)
	b.SetTimeout(framework.DefaultTimeout)

	// Apply configuration if provided
	if len(conf.Config) > 0 {
		if err := ValidateConfig(conf.Config); err != nil {
			return nil, fmt.Errorf("invalid configuration: %w", err)
		}
		parsedConfig := parseConfig(conf.Config)
		b.SetMaxBodySize(parsedConfig.MaxBodySize)
		b.SetTimeout(parsedConfig.Timeout)
		b.setTLSSettings(parsedConfig.TLSSkipVerify, parsedConfig.CAData)
		b.setHostAllowlist(parsedConfig.AllowedHosts)

		// Update transport if custom TLS config is set
		if parsedConfig.TLSSkipVerify || parsedConfig.CAData != "" {
			transport, err := newTransportWithTLS(parsedConfig.CAData, parsedConfig.TLSSkipVerify)
			if err != nil {
				return nil, fmt.Errorf("invalid TLS configuration: %w", err)
			}
			b.SetTransport(transport)
		}

		b.StreamingBackend.SetTransparentConfig(&framework.TransparentConfig{
			AutoAuthPath:    parsedConfig.AutoAuthPath,
			UserAuthPath:    parsedConfig.UserAuthPath,
			UserAuthRole:    parsedConfig.UserAuthRole,
			DefaultAuthRole: parsedConfig.DefaultAuthRole,
		})
	}

	return b, nil
}

// Initialize loads persisted config from storage
func (b *azureBackend) Initialize(ctx context.Context) error {
	if b.StorageView == nil {
		return nil
	}
	// The mount is routed before it is initialized, so a config write can
	// arrive now; it must not interleave with loading or seeding the stored
	// config, or the seeded defaults could overwrite what it persisted.
	b.configWriteMu.Lock()
	defer b.configWriteMu.Unlock()

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
			UserAuthPath    string `json:"user_auth_path"`
			UserAuthRole    string `json:"user_auth_role"`
			DefaultAuthRole string `json:"default_role"`
			AllowedHosts    any    `json:"allowed_host_suffixes"`
		}
		if err := entry.DecodeJSON(&config); err != nil {
			return fmt.Errorf("failed to decode config: %w", err)
		}
		// Writes are validated, so a bad stored allowlist means the entry was
		// changed behind them. The default is the narrowest list there is: fall
		// back to it rather than leave the rest of the config unloaded.
		allowedHosts, err := framework.ParseHostAllowlist(config.AllowedHosts)
		if err != nil {
			b.Logger.Warn("ignoring invalid stored host allowlist; keeping the default", logger.Err(err))
			allowedHosts = nil
		}
		b.SetMaxBodySize(config.MaxBodySize)
		b.setTLSSettings(config.TLSSkipVerify, config.CAData)
		b.setHostAllowlist(allowedHosts)
		if config.Timeout != "" {
			// A stored zero keeps the default: the timeout is the only bound
			// on how long an upstream may take.
			if timeout, err := time.ParseDuration(config.Timeout); err == nil && timeout > 0 {
				b.SetTimeout(timeout)
			} else if err == nil {
				b.Logger.Warn("ignoring stored timeout that is not positive; keeping the default",
					logger.String("timeout", config.Timeout),
					logger.String("default", b.Timeout().String()))
			}
		}

		// Update transport if custom TLS config is set
		if config.TLSSkipVerify || config.CAData != "" {
			transport, err := newTransportWithTLS(config.CAData, config.TLSSkipVerify)
			if err != nil {
				return fmt.Errorf("invalid TLS configuration: %w", err)
			}
			b.SetTransport(transport)
		}

		b.StreamingBackend.SetTransparentConfig(&framework.TransparentConfig{
			AutoAuthPath:    config.AutoAuthPath,
			UserAuthPath:    config.UserAuthPath,
			UserAuthRole:    config.UserAuthRole,
			DefaultAuthRole: config.DefaultAuthRole,
		})
	} else {
		// No persisted config — persist the defaults so a newly enabled
		// Azure provider is immediately configured and readable.
		tc := b.TransparentConfig()
		skipVerify, caData := b.tlsSettings()
		defaultEntry, err := sdklogical.StorageEntryJSON("config", map[string]any{
			"max_body_size":   b.MaxBodySize(),
			"timeout":         b.Timeout().String(),
			"tls_skip_verify": skipVerify,
			"ca_data":         caData,
			"auto_auth_path":  tc.AutoAuthPath,
			"default_role":    tc.DefaultAuthRole,
			"user_auth_path":  tc.UserAuthPath,
			"user_auth_role":  tc.UserAuthRole,

			framework.HostAllowlistKey: b.configuredHostAllowlist(),
		})
		if err != nil {
			return fmt.Errorf("failed to create default config entry: %w", err)
		}
		if err := b.StorageView.Put(ctx, defaultEntry); err != nil {
			return fmt.Errorf("failed to persist default config: %w", err)
		}
		b.Logger.Info("persisted default configuration for new Azure provider")
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

// handleTransparentGatewayStreaming handles gateway requests with implicit auth.
// The implicit auth has already been performed by the core request handler.
// This method rewrites the path and delegates to the standard gateway handler.
func (b *azureBackend) handleTransparentGatewayStreaming(ctx context.Context, req *logical.Request, fd *framework.FieldData) error {
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
	if err := framework.ValidateAllowedKeys(config,
		"max_body_size", "timeout", "tls_skip_verify", "ca_data",
		"auto_auth_path", "default_role", "user_auth_path", "user_auth_role",
		framework.HostAllowlistKey); err != nil {
		return err
	}
	if _, err := framework.ParseHostAllowlist(config[framework.HostAllowlistKey]); err != nil {
		return err
	}
	if err := framework.ValidateCommonConfig(config); err != nil {
		return err
	}
	// Validate the secondary (user) auth fields at mount-enable too, not only
	// on the config-write endpoint, so a role without a path is rejected rather
	// than silently ignored at runtime.
	if err := framework.ValidateUserAuthConfig(config); err != nil {
		return err
	}
	return framework.ValidateTLSConfig(config)
}

// SensitiveConfigFields returns the list of config fields that should be masked in output
func (b *azureBackend) SensitiveConfigFields() []string {
	return []string{"ca_data"}
}

const azureBackendHelp = `
The Azure provider enables proxying requests to Azure services with automatic
credential management and Bearer token injection.

Warden performs implicit authentication on every request and obtains an Azure
AD Bearer token from the credential manager — minted by exchanging the spec's
pre-provisioned service principal credentials — and injects it into the proxied
request's Authorization header. This allows Warden to broker Azure access
without exposing SP credentials to clients.

The gateway path format is:
  /azure/gateway/{azure-host}/{path}

The {azure-host} segment determines which Azure endpoint receives the request.
Only hosts in allowed_host_suffixes are reached; the provider proxies to them
over HTTPS. The default allows the public cloud's Resource Manager, Graph, Key
Vault, Storage (blob, queue, table, file, dfs), Azure OpenAI, Azure AI services
and Azure AI Foundry endpoints. Sovereign clouds and other endpoints must be
added.

Examples:
  /azure/gateway/management.azure.com/subscriptions?api-version=2022-12-01
  /azure/gateway/myvault.vault.azure.net/secrets/mysecret?api-version=7.4
  /azure/gateway/mystorage.blob.core.windows.net/container/blob
  /azure/gateway/graph.microsoft.com/v1.0/me

The role can be provided via the X-Warden-Role header, or embedded in
the URL path:
  /azure/role/{role}/gateway/{azure-host}/{path}

Supported Azure services (non-exhaustive):
- Azure Resource Manager (management.azure.com)
- Azure Key Vault (*.vault.azure.net)
- Azure Storage (*.blob.core.windows.net, *.queue.core.windows.net, etc.)
- Microsoft Graph (graph.microsoft.com)

Configuration:
- max_body_size: Maximum request body size (default: 10MB, max: 100MB)
- timeout: Request timeout duration (e.g., '30s', '5m')
- auto_auth_path: Auth mount path for implicit authentication (e.g., 'auth/jwt/')
- default_role: Fallback role when not specified in the URL path
- allowed_host_suffixes: Hosts the gateway forwards to, each with a leading
  dot; '.example.com' allows example.com and every host under it
`
