package alicloud

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/sigv4"
)

// alicloudBackend is the streaming backend for Alicloud provider operations.
type alicloudBackend struct {
	*framework.StreamingBackend

	// s3Signer is used for re-signing OSS (S3-compatible) requests.
	// DisableURIPathEscaping matches AWS S3 / Alicloud OSS behavior.
	s3Signer *v4.Signer

	mu            sync.RWMutex
	tlsSkipVerify bool
	caData        string
	proxyDomains  []string
}

// getProxyDomains returns a snapshot of the configured proxy domains under
// the backend's read lock.
func (b *alicloudBackend) getProxyDomains() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if len(b.proxyDomains) == 0 {
		return nil
	}
	out := make([]string, len(b.proxyDomains))
	copy(out, b.proxyDomains)
	return out
}

// Compile-time interface assertion — the provider participates in transparent
// auth by extracting the role name from the incoming ACS3 Authorization header
// (for cert-based implicit auth).
var _ logical.TransparentAuthRoleExtractor = (*alicloudBackend)(nil)

// extractToken extracts the client token from the request.
// For Alicloud, the JWT is embedded in Alicloud's own auth protocol (mirroring AWS):
//   - ACS3 JWT: JWT in x-acs-security-token (eyJ prefix)
//   - ACS3 cert: role name as access_key_id in ACS3 Credential field
//   - OSS/SigV4 JWT: JWT in X-Amz-Security-Token (eyJ prefix)
//   - OSS/SigV4 cert: role name as access_key_id in SigV4 Credential field
func extractToken(r *http.Request) string {
	// ACS3 JWT transparent
	if tok := r.Header.Get(HeaderACSSecurityToken); strings.HasPrefix(tok, "eyJ") {
		return tok
	}
	// OSS/SigV4 JWT transparent
	if tok := r.Header.Get("X-Amz-Security-Token"); strings.HasPrefix(tok, "eyJ") {
		return tok
	}
	// ACS3 cert transparent
	if IsACS3Request(r) {
		return ExtractACS3AccessKeyID(r.Header.Get(HeaderAuthorization))
	}
	// OSS/SigV4 cert transparent
	if sigv4.IsSigV4Request(r) {
		return sigv4.ExtractAccessKeyID(r.Header.Get(HeaderAuthorization))
	}
	return ""
}

// GetAuthRoleFromRequest extracts the auth role from the ACS3 or SigV4
// Authorization header. For cert transparent auth, the access_key_id is the
// role name. For JWT transparent auth, returns "" (role comes from path).
func (b *alicloudBackend) GetAuthRoleFromRequest(r *http.Request) (string, bool) {
	var accessKeyID string
	authHeader := r.Header.Get(HeaderAuthorization)
	switch {
	case IsACS3Request(r):
		accessKeyID = ExtractACS3AccessKeyID(authHeader)
	case sigv4.IsSigV4Request(r):
		accessKeyID = sigv4.ExtractAccessKeyID(authHeader)
	default:
		return "", false
	}
	if accessKeyID == "" {
		return "", false
	}
	// JWT tokens start with "eyJ" — they carry auth identity, not the role name
	if strings.HasPrefix(accessKeyID, "eyJ") {
		return "", false
	}
	return accessKeyID, true
}

// Factory creates a new Alicloud provider backend.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &alicloudBackend{
		s3Signer: v4.NewSigner(func(o *v4.SignerOptions) {
			o.DisableURIPathEscaping = true
		}),
	}

	b.StreamingBackend = &framework.StreamingBackend{
		StreamingPaths: []*framework.StreamingPath{
			{
				Pattern:         "gateway",
				Handler:         b.handleGatewayStreaming,
				HelpSynopsis:    "Alicloud Gateway proxy",
				HelpDescription: "Proxies requests to Alibaba Cloud APIs with ACS3 signature verification and re-signing",
			},
			{
				Pattern:         "gateway/.*",
				Handler:         b.handleGatewayStreaming,
				HelpSynopsis:    "Alicloud Gateway proxy",
				HelpDescription: "Proxies requests to Alibaba Cloud APIs with ACS3 signature verification and re-signing",
			},
			{
				Pattern:         "role/[^/]+/gateway",
				Handler:         b.handleGatewayStreaming,
				HelpSynopsis:    "Alicloud Transparent Gateway proxy",
				HelpDescription: "Proxies requests to Alibaba Cloud APIs with role embedded in URL path",
			},
			{
				Pattern:         "role/[^/]+/gateway/.*",
				Handler:         b.handleGatewayStreaming,
				HelpSynopsis:    "Alicloud Transparent Gateway proxy",
				HelpDescription: "Proxies requests to Alibaba Cloud APIs with role embedded in URL path",
			},
		},
		TransparentConfig: &framework.TransparentConfig{
			AutoAuthPath:    "",
			DefaultAuthRole: "",
		},
		Backend: &framework.Backend{
			Help:           alicloudBackendHelp,
			BackendType:    "alicloud",
			BackendClass:   logical.ClassProvider,
			TokenExtractor: extractToken,
			Paths:          b.paths(),
		},
	}

	b.Logger = conf.Logger.WithSubsystem("alicloud")
	b.StorageView = conf.StorageView

	initTransport()
	b.StreamingBackend.InitProxy(sharedTransport)

	if conf.RegisterShutdownHook != nil {
		conf.RegisterShutdownHook("alicloud-transport", ShutdownHTTPTransport)
	}

	if err := b.StreamingBackend.Setup(ctx, conf); err != nil {
		return nil, err
	}

	b.MaxBodySize = framework.DefaultMaxBodySize
	b.Timeout = DefaultTimeout

	if len(conf.Config) > 0 {
		if err := ValidateConfig(conf.Config); err != nil {
			return nil, fmt.Errorf("invalid configuration: %w", err)
		}
		parsed := parseConfig(conf.Config)
		b.MaxBodySize = parsed.MaxBodySize
		b.Timeout = parsed.Timeout
		b.tlsSkipVerify = parsed.TLSSkipVerify
		b.caData = parsed.CAData
		b.proxyDomains = parsed.ProxyDomains

		if b.tlsSkipVerify || b.caData != "" {
			transport, err := newTransportWithTLS(b.caData, b.tlsSkipVerify)
			if err != nil {
				return nil, fmt.Errorf("invalid TLS configuration: %w", err)
			}
			b.Proxy.Transport = transport
		}

		b.StreamingBackend.SetTransparentConfig(&framework.TransparentConfig{
			AutoAuthPath:    parsed.AutoAuthPath,
			DefaultAuthRole: parsed.DefaultAuthRole,
		})
	}

	return b, nil
}

// Initialize loads persisted config from storage.
func (b *alicloudBackend) Initialize(ctx context.Context) error {
	if b.StorageView == nil {
		return nil
	}

	entry, err := b.StorageView.Get(ctx, "config")
	if err != nil {
		return fmt.Errorf("failed to read config from storage: %w", err)
	}
	if entry != nil {
		var config struct {
			MaxBodySize     int64    `json:"max_body_size"`
			Timeout         string   `json:"timeout"`
			TLSSkipVerify   bool     `json:"tls_skip_verify"`
			CAData          string   `json:"ca_data"`
			AutoAuthPath    string   `json:"auto_auth_path"`
			DefaultAuthRole string   `json:"default_role"`
			ProxyDomains    []string `json:"proxy_domains"`
		}
		if err := entry.DecodeJSON(&config); err != nil {
			return fmt.Errorf("failed to decode config: %w", err)
		}

		b.mu.Lock()
		if config.MaxBodySize > 0 {
			b.MaxBodySize = config.MaxBodySize
		}
		b.tlsSkipVerify = config.TLSSkipVerify
		b.caData = config.CAData
		b.proxyDomains = config.ProxyDomains
		if config.Timeout != "" {
			if timeout, err := time.ParseDuration(config.Timeout); err == nil {
				b.Timeout = timeout
			}
		}
		b.mu.Unlock()

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
		// Persist defaults on first run
		tc := b.TransparentConfig
		defaultEntry, err := sdklogical.StorageEntryJSON("config", map[string]any{
			"max_body_size":   b.MaxBodySize,
			"timeout":         b.Timeout.String(),
			"tls_skip_verify": b.tlsSkipVerify,
			"ca_data":         b.caData,
			"auto_auth_path":  tc.AutoAuthPath,
			"default_role":    tc.DefaultAuthRole,
			"proxy_domains":   b.proxyDomains,
		})
		if err != nil {
			return fmt.Errorf("failed to create default config entry: %w", err)
		}
		if err := b.StorageView.Put(ctx, defaultEntry); err != nil {
			return fmt.Errorf("failed to persist default config: %w", err)
		}
		b.Logger.Info("persisted default configuration for new Alicloud provider")
	}
	return nil
}

// paths returns the configuration paths for the Alicloud provider.
func (b *alicloudBackend) paths() []*framework.Path {
	return []*framework.Path{
		b.pathConfig(),
	}
}

// handleGatewayStreaming wraps handleGateway for the streaming path handler.
func (b *alicloudBackend) handleGatewayStreaming(ctx context.Context, req *logical.Request, fd *framework.FieldData) error {
	b.handleGateway(ctx, req)
	return nil
}

// SensitiveConfigFields returns the list of config fields that should be masked in output.
func (b *alicloudBackend) SensitiveConfigFields() []string {
	return []string{"ca_data"}
}

const alicloudBackendHelp = `
The Alibaba Cloud (Alicloud) provider enables proxying requests to Alicloud
OpenAPI endpoints with automatic credential management and ACS3-HMAC-SHA256
signature re-signing.

Warden is transparent to Alicloud clients: clients use a standard Alicloud SDK
pointed at the Warden mount, and sign requests using their Warden-issued
identity (a JWT used as access_key_secret + x-acs-security-token, or a role
name used as both access_key_id and access_key_secret for cert auth). Warden
verifies the incoming signature for request integrity, re-signs with real
Alicloud credentials from the credential manager, and forwards the request.

The gateway path format is:
  /alicloud/gateway/{api-path}

The role can be embedded in the URL path:
  /alicloud/role/{role}/gateway/{api-path}

Clients set the Host header (via their SDK's endpoint configuration) to the
target Alicloud service, e.g.:
  - ecs.cn-hangzhou.aliyuncs.com (ECS)
  - ram.aliyuncs.com (RAM)
  - sts.aliyuncs.com (STS)
  - kms.cn-hangzhou.aliyuncs.com (KMS)

Credential type: alicloud_keys
  - access_key_id: Alicloud access key ID
  - access_key_secret: Alicloud access key secret
  - security_token: Optional STS security token (for temporary credentials)

Configuration:
- max_body_size: Maximum request body size (default: 10MB, max: 100MB)
- timeout: Request timeout duration (default: 30s)
- auto_auth_path: Auth mount path for implicit authentication (e.g., 'auth/jwt/')
- default_role: Fallback role when not specified
`
