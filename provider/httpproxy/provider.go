package httpproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

// TokenExtractorFunc extracts the Warden session token from an incoming HTTP request.
type TokenExtractorFunc func(r *http.Request) string

// ProviderSpec fully describes an HTTP proxy provider.
// All shared behavior is handled by the httpproxy package; only provider-specific
// differences are captured here.
type ProviderSpec struct {
	// Name is the provider identifier (e.g., "openai", "anthropic").
	Name string

	// DefaultURL is the upstream API base URL (e.g., "https://api.openai.com").
	DefaultURL string

	// URLConfigKey is the config key for the URL (e.g., "openai_url").
	URLConfigKey string

	// DefaultTimeout is the default request timeout.
	DefaultTimeout time.Duration

	// ParseStreamBody enables request body parsing for policy evaluation.
	ParseStreamBody bool

	// UserAgent is the User-Agent string for proxied requests.
	// If empty, defaults to "warden-{Name}-proxy".
	UserAgent string

	// HelpText is the backend help description.
	HelpText string

	// ExtractCredentials extracts credentials from the request and returns
	// headers to inject into the proxied request.
	ExtractCredentials CredentialExtractor

	// ExtractToken optionally overrides token extraction from HTTP requests.
	// If nil, uses DefaultTokenExtractor (X-Warden-Token / Authorization: Bearer).
	ExtractToken TokenExtractorFunc

	// ExtraHeadersToRemove are provider-specific headers to strip beyond the base set.
	ExtraHeadersToRemove []string

	// DefaultHeaders are static headers always set on proxied requests (e.g., "anthropic-version").
	DefaultHeaders map[string]string

	// DynamicHeaders returns headers to set based on current config state.
	// Called on every request. Use for headers derived from config values.
	DynamicHeaders func(state map[string]any) map[string]string

	// DefaultAccept overrides the default Accept header (defaults to "application/json").
	DefaultAccept string

	// ExtraConfigFields defines additional config fields beyond the standard set.
	ExtraConfigFields map[string]*framework.FieldSchema

	// OnConfigRead is called during config read to add extra fields to the response.
	OnConfigRead func(state map[string]any) map[string]any

	// OnConfigWrite is called during config write to process extra fields.
	OnConfigWrite func(d *framework.FieldData, state map[string]any) (map[string]any, error)

	// OnInitialize is called during Initialize to load extra fields from persisted config.
	OnInitialize func(config map[string]any, state map[string]any) map[string]any

	// ValidateExtraConfig is called during config validation for extra fields.
	// If nil, no extra validation is performed beyond the standard fields.
	ValidateExtraConfig func(conf map[string]any) error

	// NewTransport creates the shared HTTP transport for this provider type.
	// Called lazily on first backend instantiation via sync.Once.
	// Returns the transport and a shutdown function.
	// If nil, DefaultNewTransport is used.
	NewTransport func() (*http.Transport, func())
}

// proxyBackend is the concrete backend type created by NewFactory.
type proxyBackend struct {
	*framework.StreamingBackend
	providerURL   string
	spec          *ProviderSpec
	extraState    map[string]any
	mu            sync.RWMutex
	tlsSkipVerify bool
	caData        string
}

// NewFactory creates a logical.Factory from a ProviderSpec.
func NewFactory(spec *ProviderSpec) logical.Factory {
	newTransport := spec.NewTransport
	if newTransport == nil {
		newTransport = DefaultNewTransport
	}

	var (
		sharedTransport *http.Transport
		shutdownFn      func()
		transportOnce   sync.Once
	)

	return func(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
		transportOnce.Do(func() {
			sharedTransport, shutdownFn = newTransport()
		})
		b := &proxyBackend{
			spec:       spec,
			extraState: make(map[string]any),
		}

		tokenExtractor := spec.ExtractToken
		if tokenExtractor == nil {
			tokenExtractor = DefaultTokenExtractor
		}

		b.StreamingBackend = &framework.StreamingBackend{
			StreamingPaths: []*framework.StreamingPath{
				{
					Pattern:         "gateway",
					Handler:         b.handleGatewayStreaming,
					HelpSynopsis:    spec.Name + " Gateway proxy",
					HelpDescription: "Proxies requests to " + spec.Name + " API with credential injection",
				},
				{
					Pattern:         "gateway/.*",
					Handler:         b.handleGatewayStreaming,
					HelpSynopsis:    spec.Name + " Gateway proxy",
					HelpDescription: "Proxies requests to " + spec.Name + " API with credential injection",
				},
				{
					Pattern:         "role/[^/]+/gateway",
					Handler:         b.handleTransparentGatewayStreaming,
					HelpSynopsis:    spec.Name + " Transparent Gateway proxy",
					HelpDescription: "Proxies requests to " + spec.Name + " API with role embedded in URL path",
				},
				{
					Pattern:         "role/[^/]+/gateway/.*",
					Handler:         b.handleTransparentGatewayStreaming,
					HelpSynopsis:    spec.Name + " Transparent Gateway proxy",
					HelpDescription: "Proxies requests to " + spec.Name + " API with role embedded in URL path",
				},
			},
			ParseStreamBody: spec.ParseStreamBody,
			TransparentConfig: &framework.TransparentConfig{
				AutoAuthPath:    "",
				DefaultAuthRole: "",
			},
			Backend: &framework.Backend{
				Help:           spec.HelpText,
				BackendType:    spec.Name,
				BackendClass:   logical.ClassProvider,
				TokenExtractor: tokenExtractor,
				Paths:          b.paths(),
			},
		}

		// Set common fields
		b.Logger = conf.Logger.WithSubsystem(spec.Name)
		b.StorageView = conf.StorageView

		// Initialize reverse proxy with provider-type shared transport
		b.StreamingBackend.InitProxy(sharedTransport)

		// Register transport shutdown hook
		if conf.RegisterShutdownHook != nil && shutdownFn != nil {
			conf.RegisterShutdownHook(spec.Name+"-transport", shutdownFn)
		}

		if err := b.StreamingBackend.Setup(ctx, conf); err != nil {
			return nil, err
		}

		// Set defaults
		b.MaxBodySize = framework.DefaultMaxBodySize
		b.Timeout = spec.DefaultTimeout
		b.providerURL = spec.DefaultURL

		// Apply configuration if provided
		if len(conf.Config) > 0 {
			if err := ValidateConfig(conf.Config, spec.URLConfigKey); err != nil {
				return nil, fmt.Errorf("invalid configuration: %w", err)
			}
			if spec.ValidateExtraConfig != nil {
				if err := spec.ValidateExtraConfig(conf.Config); err != nil {
					return nil, fmt.Errorf("invalid configuration: %w", err)
				}
			}
			parsedConfig := ParseConfig(conf.Config, spec.URLConfigKey, spec.DefaultURL, spec.DefaultTimeout)
			b.providerURL = strings.TrimRight(parsedConfig.ProviderURL, "/")
			b.MaxBodySize = parsedConfig.MaxBodySize
			b.Timeout = parsedConfig.Timeout

			b.StreamingBackend.SetTransparentConfig(&framework.TransparentConfig{
				AutoAuthPath:    parsedConfig.AutoAuthPath,
				DefaultAuthRole: parsedConfig.DefaultAuthRole,
			})

			// Apply TLS configuration if provided
			if parsedConfig.CAData != "" || parsedConfig.TLSSkipVerify {
				transport, err := NewTransportWithTLS(parsedConfig.CAData, parsedConfig.TLSSkipVerify)
				if err != nil {
					return nil, fmt.Errorf("invalid TLS configuration: %w", err)
				}
				b.Proxy.Transport = transport
				b.tlsSkipVerify = parsedConfig.TLSSkipVerify
				b.caData = parsedConfig.CAData
			}

			// Process extra config fields
			if spec.OnInitialize != nil {
				b.extraState = spec.OnInitialize(conf.Config, b.extraState)
			}
		}

		return b, nil
	}
}

// Initialize loads persisted config from storage.
func (b *proxyBackend) Initialize(ctx context.Context) error {
	if b.StorageView == nil {
		return nil
	}

	entry, err := b.StorageView.Get(ctx, "config")
	if err != nil {
		return fmt.Errorf("failed to read config from storage: %w", err)
	}
	if entry != nil {
		var config map[string]any
		if err := entry.DecodeJSON(&config); err != nil {
			return fmt.Errorf("failed to decode config: %w", err)
		}

		if urlVal, ok := config[b.spec.URLConfigKey].(string); ok && urlVal != "" {
			b.providerURL = strings.TrimRight(urlVal, "/")
		}

		// Parse max_body_size from persisted config
		if maxSize, ok := config["max_body_size"]; ok {
			switch v := maxSize.(type) {
			case float64:
				b.MaxBodySize = int64(v)
			case int64:
				b.MaxBodySize = v
			case json.Number:
				if parsed, err := v.Int64(); err == nil {
					b.MaxBodySize = parsed
				}
			}
		}

		if timeoutStr, ok := config["timeout"].(string); ok && timeoutStr != "" {
			if timeout, err := time.ParseDuration(timeoutStr); err == nil {
				b.Timeout = timeout
			}
		}

		autoAuthPath, _ := config["auto_auth_path"].(string)
		defaultRole, _ := config["default_role"].(string)
		b.StreamingBackend.SetTransparentConfig(&framework.TransparentConfig{
			AutoAuthPath:    autoAuthPath,
			DefaultAuthRole: defaultRole,
		})

		// Load TLS configuration
		skipVerify, _ := config["tls_skip_verify"].(bool)
		caData, _ := config["ca_data"].(string)
		if caData != "" || skipVerify {
			transport, err := NewTransportWithTLS(caData, skipVerify)
			if err != nil {
				return fmt.Errorf("failed to configure TLS: %w", err)
			}
			b.Proxy.Transport = transport
			b.tlsSkipVerify = skipVerify
			b.caData = caData
		}

		// Load extra state
		if b.spec.OnInitialize != nil {
			b.mu.Lock()
			b.extraState = b.spec.OnInitialize(config, b.extraState)
			b.mu.Unlock()
		}
	} else {
		// No persisted config — persist defaults
		tc := b.TransparentConfig
		configData := map[string]any{
			b.spec.URLConfigKey: b.providerURL,
			"max_body_size":     b.MaxBodySize,
			"timeout":           b.Timeout.String(),
			"auto_auth_path":    tc.AutoAuthPath,
			"default_role":      tc.DefaultAuthRole,
			"tls_skip_verify":   b.tlsSkipVerify,
			"ca_data":           b.caData,
		}

		// Add extra state defaults
		if b.spec.OnConfigRead != nil {
			b.mu.RLock()
			for k, v := range b.spec.OnConfigRead(b.extraState) {
				configData[k] = v
			}
			b.mu.RUnlock()
		}

		defaultEntry, err := sdklogical.StorageEntryJSON("config", configData)
		if err != nil {
			return fmt.Errorf("failed to create default config entry: %w", err)
		}
		if err := b.StorageView.Put(ctx, defaultEntry); err != nil {
			return fmt.Errorf("failed to persist default config: %w", err)
		}
		b.Logger.Info("persisted default configuration for new " + b.spec.Name + " provider")
	}
	return nil
}

// paths returns the configuration paths for the provider.
func (b *proxyBackend) paths() []*framework.Path {
	return []*framework.Path{
		b.pathConfig(),
	}
}

// handleGatewayStreaming handles streaming gateway requests.
func (b *proxyBackend) handleGatewayStreaming(ctx context.Context, req *logical.Request, fd *framework.FieldData) error {
	b.handleGateway(ctx, req)
	return nil
}

// handleTransparentGatewayStreaming handles gateway requests with implicit auth.
func (b *proxyBackend) handleTransparentGatewayStreaming(ctx context.Context, req *logical.Request, fd *framework.FieldData) error {
	req.Path = b.StreamingBackend.RewriteTransparentPath(req.Path)
	if req.HTTPRequest != nil && req.HTTPRequest.URL != nil {
		req.HTTPRequest.URL.Path = b.StreamingBackend.RewriteTransparentPath(req.HTTPRequest.URL.Path)
	}
	b.handleGateway(ctx, req)
	return nil
}

// SensitiveConfigFields returns the list of config fields that should be masked in output.
func (b *proxyBackend) SensitiveConfigFields() []string {
	return []string{"ca_data"}
}
