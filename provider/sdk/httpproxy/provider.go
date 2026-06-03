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

// Dispatch carries per-request overrides returned by ProviderSpec.ResolveUpstream.
// Zero values mean "fall through to the spec/mount default." Used by providers
// that carry multiple protocols on the same mount and need different upstreams,
// credential formats, header policies, or size caps depending on the path.
type Dispatch struct {
	// UpstreamURL overrides providerURL for this request.
	UpstreamURL string

	// ExtractCredentials overrides Spec.ExtractCredentials for this request.
	ExtractCredentials CredentialExtractor

	// Accept overrides Spec.DefaultAccept for this request. When empty, the
	// spec default applies unless SkipDefaultAccept is also set.
	Accept string

	// SkipDefaultAccept suppresses Accept injection entirely when Accept is
	// empty: no header is set and the client's own Accept negotiation is
	// preserved. Required for protocols whose clients negotiate their own
	// Accept and would be broken by a JSON default.
	SkipDefaultAccept bool

	// SkipDynamicHeaders disables Spec.DynamicHeaders injection for this
	// request. Used when the request targets a surface where the dynamic
	// headers are irrelevant or harmful.
	SkipDynamicHeaders bool

	// MaxBodySize overrides the per-mount max_body_size for this request when > 0.
	// Used by protocols that legitimately need larger caps than the REST default
	// (e.g. uploading large binary payloads). When 0, falls through to b.MaxBodySize.
	MaxBodySize int64

	// BypassBodyParsing suppresses the framework's request-body parsing step for
	// this request even when the backend has ParseStreamBody=true. Used by
	// protocols whose request bodies are binary (and would be wasteful or
	// harmful to parse as JSON / form-urlencoded). Honoured via the proxy
	// backend's request-aware ShouldParseStreamBody implementation, which
	// consults ResolveUpstream and inspects this field.
	BypassBodyParsing bool
}

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
	// Called on every request as fallbacks — only set if the client did not
	// already provide the header. Use DefaultHeaders for headers that must
	// always override client values.
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

	// ResolveUpstream optionally returns per-request overrides for upstream
	// URL, credential extraction, header policy, and body cap. When nil — or
	// when the call returns ok=false — the spec/mount defaults apply unchanged.
	// Used by providers that carry multiple protocols on the same mount and
	// need to route a subset of paths to a different upstream surface.
	//
	// state is the backend's extraState — the same map populated by
	// OnInitialize/OnConfigWrite and read by DynamicHeaders. The reference is
	// handed off after a read-lock snapshot; the closure must NOT mutate the
	// map (concurrent writers replace the reference under the write lock, so
	// in-place mutation here would race). Reads are safe because OnConfigWrite
	// receives a clone, so the live map is never mutated in place.
	ResolveUpstream func(r *http.Request, providerURL string, state map[string]any) (Dispatch, bool)

	// GetAuthRoleFromRequest optionally extracts the auth role from request
	// context. The shared httpproxy backend wires this into the core's
	// TransparentAuthRoleExtractor flow, so the spec hook is consulted only
	// when the path-based role lookup is empty and BEFORE the X-Warden-Role
	// header override but BEFORE the mount's default_role fallback.
	//
	// Return "" for "no role contribution — caller falls back to default_role";
	// this is also the default behaviour when the hook is unset. Return a
	// non-empty role to supply a role for this request.
	GetAuthRoleFromRequest func(r *http.Request) string

	// IsUnauthenticatedRequest optionally lets the provider declare that a
	// specific request should bypass authentication and pass through to the
	// upstream. Consulted by the shared httpproxy backend's
	// IsUnauthenticatedPath implementation; if the hook returns true the
	// request is treated as unauthenticated. If it returns false (or the hook
	// is unset), the static StreamingBackend.UnauthenticatedPaths list still
	// applies as a fallback — providers can rely on both mechanisms.
	//
	// Used by providers whose mount carries a protocol that probes for auth
	// (Git smart-HTTP first probe → upstream WWW-Authenticate → client retry
	// with Basic Auth) where the same path is "unauth" on the probe and
	// "auth-required" on the retry. The hook receives the parsed HTTP
	// request and the mount-relative path so it can correlate headers and
	// path shape.
	//
	// The handler still runs for unauthenticated requests; req.Credential
	// will be nil, so providers must ensure their gateway path is safe to
	// invoke without minted credentials (see gateway.go's
	// StreamUnauthenticated guard).
	IsUnauthenticatedRequest func(r *http.Request, path string) bool

	// ShouldEnforceMCPPolicy optionally opts this provider into CBP
	// `mcp { }` body-authoritative policy enforcement. When set, the
	// core handler calls this hook on every request matched to this
	// backend; if it returns true the request body is buffered and
	// strict-parsed as JSON-RPC before policy evaluation runs. The
	// shared proxyBackend implements logical.MCPPolicyEnforced by
	// delegating to this hook.
	//
	// Returning true on traffic that is not a JSON-RPC POST will deny
	// the request at policy eval time (the parser fails closed on
	// non-JSON or empty bodies). MCP providers should gate on method +
	// Content-Type to leave SSE GETs and session-close DELETEs alone.
	//
	// MCP-enforcing specs MUST set ParseStreamBody: false. Opting into
	// the framework's stream-body parser would consume the body before
	// the MCP extractor runs.
	ShouldEnforceMCPPolicy func(req *logical.Request) bool
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

		// Seed an empty transparent config; SetTransparentConfig below replaces it
		// if conf.Config carries non-empty values.
		b.StreamingBackend.SetTransparentConfig(&framework.TransparentConfig{})

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
		b.SetMaxBodySize(framework.DefaultMaxBodySize)
		b.SetTimeout(spec.DefaultTimeout)
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
			b.SetMaxBodySize(parsedConfig.MaxBodySize)
			b.SetTimeout(parsedConfig.Timeout)

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
				b.SetTransport(transport)
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

		b.mu.Lock()
		if urlVal, ok := config[b.spec.URLConfigKey].(string); ok && urlVal != "" {
			b.providerURL = strings.TrimRight(urlVal, "/")
		}

		// Parse max_body_size from persisted config
		if maxSize, ok := config["max_body_size"]; ok {
			if size, parsed := ReadInt64Config(maxSize); parsed {
				b.SetMaxBodySize(size)
			}
		}

		if timeoutStr, ok := config["timeout"].(string); ok && timeoutStr != "" {
			if timeout, err := time.ParseDuration(timeoutStr); err == nil {
				b.SetTimeout(timeout)
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
				b.mu.Unlock()
				return fmt.Errorf("failed to configure TLS: %w", err)
			}
			b.SetTransport(transport)
			b.tlsSkipVerify = skipVerify
			b.caData = caData
		}

		// Load extra state
		if b.spec.OnInitialize != nil {
			b.extraState = b.spec.OnInitialize(config, b.extraState)
		}
		b.mu.Unlock()
	} else {
		// No persisted config — persist defaults
		tc := b.TransparentConfig()
		b.mu.RLock()
		configData := map[string]any{
			b.spec.URLConfigKey: b.providerURL,
			"max_body_size":     b.MaxBodySize(),
			"timeout":           b.Timeout().String(),
			"auto_auth_path":    tc.AutoAuthPath,
			"default_role":      tc.DefaultAuthRole,
			"tls_skip_verify":   b.tlsSkipVerify,
			"ca_data":           b.caData,
		}

		// Add extra state defaults
		if b.spec.OnConfigRead != nil {
			for k, v := range b.spec.OnConfigRead(b.extraState) {
				configData[k] = v
			}
		}
		b.mu.RUnlock()

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

// Compile-time assertion that proxyBackend satisfies the role-extractor
// interface. The implementation delegates to spec.GetAuthRoleFromRequest;
// providers that leave the hook nil get "" — observationally equivalent to
// not implementing the interface.
var _ logical.TransparentAuthRoleExtractor = (*proxyBackend)(nil)

// Compile-time assertion that proxyBackend satisfies TransparentModeProvider.
// Satisfaction is inherited from the embedded StreamingBackend, but the
// override on IsUnauthenticatedPath shadows the embedded method — this
// assertion catches regressions where someone changes the override
// signature in a way that breaks interface satisfaction.
var _ logical.TransparentModeProvider = (*proxyBackend)(nil)

// GetAuthRoleFromRequest delegates to the optional spec hook. See
// ProviderSpec.GetAuthRoleFromRequest for the contract.
func (b *proxyBackend) GetAuthRoleFromRequest(r *http.Request) string {
	if b.spec.GetAuthRoleFromRequest == nil {
		return ""
	}
	return b.spec.GetAuthRoleFromRequest(r)
}

// IsUnauthenticatedPath consults the spec's IsUnauthenticatedRequest hook
// (request-aware) before falling through to the static UnauthenticatedPaths
// list on the embedded StreamingBackend. Both mechanisms compose: a
// request that the hook declines (false) can still match the static list,
// preserving the invariant that any path in UnauthenticatedPaths is always
// unauth-passable.
func (b *proxyBackend) IsUnauthenticatedPath(r *http.Request, path string) bool {
	if b.spec.IsUnauthenticatedRequest != nil && b.spec.IsUnauthenticatedRequest(r, path) {
		return true
	}
	return b.StreamingBackend.IsUnauthenticatedPath(r, path)
}

// cloneExtraState returns a shallow copy of the given extraState map. Used
// by OnConfigWrite call sites so the hook can mutate the input safely while
// concurrent gateway reads see a stable snapshot until the new state is
// swapped in under the write lock.
func cloneExtraState(src map[string]any) map[string]any {
	if src == nil {
		return nil
	}
	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// ReadInt64Config coerces a persisted config value to int64. Storage and
// JSON round-trip numeric values as float64 or json.Number depending on the
// decode path, so a value written as int64 may come back differently typed
// during OnInitialize / Initialize. Returns (value, true) on a successful
// coercion to a positive int64; (0, false) otherwise.
func ReadInt64Config(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, n > 0
	case float64:
		size := int64(n)
		return size, size > 0
	case json.Number:
		size, err := n.Int64()
		if err != nil {
			return 0, false
		}
		return size, size > 0
	}
	return 0, false
}

// ShouldEnforceMCPPolicy implements logical.MCPPolicyEnforced by
// delegating to the spec's ShouldEnforceMCPPolicy hook. Returns the
// mount-configured MaxBodySize as the cap so the core extractor uses
// the same byte-cap the gateway will enforce at proxy time. Returns
// enforce=false with cap=0 when the spec did not set the hook — every
// other httpproxy-backed provider (github, openai, slack, anthropic,
// …) sees no MCP enforcement.
func (b *proxyBackend) ShouldEnforceMCPPolicy(req *logical.Request) (bool, int64) {
	if b.spec.ShouldEnforceMCPPolicy == nil {
		return false, 0
	}
	if !b.spec.ShouldEnforceMCPPolicy(req) {
		return false, 0
	}
	// MaxBodySize is atomic on StreamingBackend — race-detector clean
	// against concurrent reconfigures without holding b.mu.
	return true, b.MaxBodySize()
}

// ShouldParseStreamBody overrides the embedded StreamingBackend's default to
// consult ResolveUpstream for a per-request BypassBodyParsing signal. Falls
// back to the static ParseStreamBody flag when no hook is set, when the hook
// returns ok=false, or when the returned Dispatch does not set
// BypassBodyParsing.
func (b *proxyBackend) ShouldParseStreamBody(r *http.Request) bool {
	if b.spec.ResolveUpstream != nil && r != nil {
		b.mu.RLock()
		providerURL := b.providerURL
		state := b.extraState
		b.mu.RUnlock()
		if d, ok := b.spec.ResolveUpstream(r, providerURL, state); ok && d.BypassBodyParsing {
			return false
		}
	}
	return b.ParseStreamBody
}
