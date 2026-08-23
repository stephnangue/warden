package dualgateway

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/sdk/sigv4"
)

// dualgatewayBackend is the generic backend for dual-mode gateway providers.
type dualgatewayBackend struct {
	*framework.StreamingBackend
	spec     *ProviderSpec
	s3Signer *v4.Signer // SigV4 signer with DisableURIPathEscaping for S3

	// configWriteMu serialises the config-write handler. mu guards individual
	// field reads and writes; this guards the whole read-merge-apply-persist
	// sequence, which mu cannot since the apply must not hold it.
	configWriteMu sync.Mutex

	mu            sync.RWMutex   // protects mutable fields below
	providerURL   string         // upstream REST API base URL
	extraState    map[string]any // provider-specific state from OnConfigParsed
	extraRaw      map[string]any // provider-specific config as the operator gave it
	tlsSkipVerify bool
	caData        string

	// installedTransport is the per-mount transport currently in use, or nil
	// when this mount rides the shared one. The framework's Transport() returns
	// a stable wrapper rather than what was installed, so a replacement cannot
	// otherwise be found again to close.
	installedTransport *http.Transport

	// configErr records a stored configuration that could not be applied at
	// load. Core logs an Initialize failure and carries on, so without this the
	// mount would keep serving on spec defaults — the vendor's public endpoint.
	configErr error
}

// Compile-time interface assertion
var _ logical.TransparentAuthRoleExtractor = (*dualgatewayBackend)(nil)

// GetAuthRoleFromRequest extracts the auth role from the SigV4 Authorization header.
// For S3 requests, the access_key_id is used as the role name (cert transparent auth).
// For JWT transparent auth, the JWT is the access_key_id and role comes from the path or X-Warden-Role.
func (b *dualgatewayBackend) GetAuthRoleFromRequest(r *http.Request) string {
	if !sigv4.IsSigV4Request(r) {
		return ""
	}
	accessKeyID := sigv4.ExtractAccessKeyID(r.Header.Get("Authorization"))
	// JWT tokens start with "eyJ" — they carry auth identity, not the role name
	if strings.HasPrefix(accessKeyID, "eyJ") {
		return ""
	}
	return accessKeyID
}

// NewFactory returns a logical.Factory that creates a dual-mode gateway backend
// from the given ProviderSpec.
func NewFactory(spec *ProviderSpec) logical.Factory {
	if err := validateSpec(spec); err != nil {
		// Return a factory that always fails — catches spec bugs at mount time
		return func(_ context.Context, _ *logical.BackendConfig) (logical.Backend, error) {
			return nil, err
		}
	}

	return func(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
		b := &dualgatewayBackend{
			spec: spec,
			s3Signer: v4.NewSigner(func(o *v4.SignerOptions) {
				o.DisableURIPathEscaping = true
			}),
			providerURL: spec.DefaultURL,
		}

		b.StreamingBackend = &framework.StreamingBackend{
			StreamingPaths: []*framework.StreamingPath{
				{
					Pattern:         "gateway",
					Handler:         b.handleGatewayStreaming,
					HelpSynopsis:    spec.Name + " Gateway proxy",
					HelpDescription: "Proxies requests to " + spec.Name + " APIs with auto-detection of standard API vs S3",
				},
				{
					Pattern:         "gateway/.*",
					Handler:         b.handleGatewayStreaming,
					HelpSynopsis:    spec.Name + " Gateway proxy",
					HelpDescription: "Proxies requests to " + spec.Name + " APIs with auto-detection of standard API vs S3",
				},
				{
					Pattern:         "role/[^/]+/gateway",
					Handler:         b.handleGatewayStreaming,
					HelpSynopsis:    spec.Name + " Transparent Gateway proxy",
					HelpDescription: "Proxies requests to " + spec.Name + " APIs with role embedded in URL path",
				},
				{
					Pattern:         "role/[^/]+/gateway/.*",
					Handler:         b.handleGatewayStreaming,
					HelpSynopsis:    spec.Name + " Transparent Gateway proxy",
					HelpDescription: "Proxies requests to " + spec.Name + " APIs with role embedded in URL path",
				},
			},
			Backend: &framework.Backend{
				Help:           spec.HelpText,
				BackendType:    spec.Name,
				BackendClass:   logical.ClassProvider,
				TokenExtractor: extractTokens,
				Paths:          b.paths(),
			},
		}

		b.Logger = conf.Logger.WithSubsystem(spec.Name)
		b.StorageView = conf.StorageView

		initTransport()
		b.StreamingBackend.InitProxy(sharedTransport)

		if conf.RegisterShutdownHook != nil {
			conf.RegisterShutdownHook(spec.Name+"-transport", ShutdownHTTPTransport)
		}

		if err := b.StreamingBackend.Setup(ctx, conf); err != nil {
			return nil, err
		}

		if len(conf.Config) > 0 {
			if err := validateConfig(spec, conf.Config); err != nil {
				return nil, fmt.Errorf("invalid configuration: %w", err)
			}
		}

		// Applied unconditionally, and only after InitProxy: an empty config
		// still has to resolve the defaults (a zero max body size reads as
		// unlimited downstream, not as "use the default"), and applying before
		// InitProxy would see a mount-time TLS transport overwritten by the
		// shared one.
		if _, err := b.applyParsedConfig(conf.Config); err != nil {
			return nil, fmt.Errorf("invalid configuration: %w", err)
		}

		return b, nil
	}
}

// Initialize loads persisted config from storage.
func (b *dualgatewayBackend) Initialize(ctx context.Context) error {
	if b.StorageView == nil {
		return nil
	}

	entry, err := b.StorageView.Get(ctx, "config")
	if err != nil {
		return fmt.Errorf("failed to read config from storage: %w", err)
	}
	if entry == nil {
		return nil
	}

	var config map[string]any
	if err := entry.DecodeJSON(&config); err != nil {
		return fmt.Errorf("failed to decode config: %w", err)
	}

	// The stored entry is authoritative and complete — a config write persists
	// the whole key set — so it replaces the mount-time configuration wholesale
	// rather than being layered over it. Routing through applyParsedConfig is
	// what makes a private CA survive a restart: rebuilt here, or the mount
	// quietly falls back to the system roots on the next unseal.
	if _, err := b.applyParsedConfig(config); err != nil {
		wrapped := fmt.Errorf("failed to apply stored config: %w", err)
		b.mu.Lock()
		b.configErr = wrapped
		b.mu.Unlock()
		return wrapped
	}

	b.mu.Lock()
	b.configErr = nil
	b.mu.Unlock()

	return nil
}

// paths returns the configuration paths for the provider.
func (b *dualgatewayBackend) paths() []*framework.Path {
	return []*framework.Path{
		b.pathConfig(),
	}
}

// handleGatewayStreaming wraps handleGateway for the streaming path handler.
func (b *dualgatewayBackend) handleGatewayStreaming(ctx context.Context, req *logical.Request, fd *framework.FieldData) error {
	b.handleGateway(ctx, req)
	return nil
}

// SensitiveConfigFields returns the list of config fields that should be masked in output.
func (b *dualgatewayBackend) SensitiveConfigFields() []string {
	return []string{"ca_data"}
}

// validateSpec checks that required ProviderSpec fields are set.
func validateSpec(spec *ProviderSpec) error {
	if spec == nil {
		return fmt.Errorf("provider spec is nil")
	}
	if spec.Name == "" {
		return fmt.Errorf("provider spec Name is required")
	}
	if spec.DefaultURL == "" {
		return fmt.Errorf("provider spec DefaultURL is required")
	}
	if spec.URLConfigKey == "" {
		return fmt.Errorf("provider spec URLConfigKey is required")
	}
	if spec.S3Endpoint == nil {
		return fmt.Errorf("provider spec S3Endpoint function is required")
	}
	if spec.APIAuth.HeaderName == "" {
		return fmt.Errorf("provider spec APIAuth.HeaderName is required")
	}
	if spec.APIAuth.HeaderValueFormat == "" {
		return fmt.Errorf("provider spec APIAuth.HeaderValueFormat is required")
	}
	if spec.APIAuth.CredentialField == "" {
		return fmt.Errorf("provider spec APIAuth.CredentialField is required")
	}
	return nil
}
