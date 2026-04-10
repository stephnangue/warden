package scaleway

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/sigv4"
)

// scalewayBackend is the backend for Scaleway provider operations
type scalewayBackend struct {
	*framework.StreamingBackend
	s3Signer    *v4.Signer // SigV4 signer with DisableURIPathEscaping for S3
	scalewayURL string     // Scaleway API base URL (default: https://api.scaleway.com)
}

// extractToken extracts the client token from the request.
// Handles three modes:
//   - Standard: X-Warden-Token or Authorization: Bearer
//   - S3 JWT transparent: JWT (eyJ prefix) in SigV4 Credential access_key_id
//   - S3 Cert transparent: role name from SigV4 Credential access_key_id
func extractToken(r *http.Request) string {
	// Standard Warden token
	if token := r.Header.Get("X-Warden-Token"); token != "" {
		return token
	}

	// Bearer token
	authHeader := r.Header.Get("Authorization")
	if len(authHeader) > 7 && strings.EqualFold(authHeader[:7], "Bearer ") {
		return authHeader[7:]
	}

	// S3 transparent: extract access_key_id from SigV4 header
	if sigv4.IsSigV4Request(r) {
		accessKeyID := sigv4.ExtractAccessKeyID(authHeader)
		if accessKeyID != "" {
			return accessKeyID
		}
	}

	return ""
}

// Compile-time interface assertion
var _ logical.TransparentAuthRoleExtractor = (*scalewayBackend)(nil)

// GetAuthRoleFromRequest extracts the auth role from the SigV4 Authorization header.
// For S3 requests, the access_key_id is used as the role name (cert transparent auth).
// For JWT transparent auth, the JWT is the access_key_id and role comes from the path or X-Warden-Role.
func (b *scalewayBackend) GetAuthRoleFromRequest(r *http.Request) (string, bool) {
	if !sigv4.IsSigV4Request(r) {
		return "", false
	}
	accessKeyID := sigv4.ExtractAccessKeyID(r.Header.Get("Authorization"))
	if accessKeyID == "" {
		return "", false
	}
	// JWT tokens start with "eyJ" — they carry auth identity, not the role name
	if strings.HasPrefix(accessKeyID, "eyJ") {
		return "", false
	}
	return accessKeyID, true
}

// Factory creates a new Scaleway provider backend
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &scalewayBackend{
		s3Signer: v4.NewSigner(func(o *v4.SignerOptions) {
			o.DisableURIPathEscaping = true
		}),
		scalewayURL: DefaultScalewayURL,
	}

	b.StreamingBackend = &framework.StreamingBackend{
		StreamingPaths: []*framework.StreamingPath{
			{
				Pattern:         "gateway",
				Handler:         b.handleGatewayStreaming,
				HelpSynopsis:    "Scaleway Gateway proxy",
				HelpDescription: "Proxies requests to Scaleway APIs with auto-detection of standard API vs S3",
			},
			{
				Pattern:         "gateway/.*",
				Handler:         b.handleGatewayStreaming,
				HelpSynopsis:    "Scaleway Gateway proxy",
				HelpDescription: "Proxies requests to Scaleway APIs with auto-detection of standard API vs S3",
			},
			{
				Pattern:         "role/[^/]+/gateway",
				Handler:         b.handleGatewayStreaming,
				HelpSynopsis:    "Scaleway Transparent Gateway proxy",
				HelpDescription: "Proxies requests to Scaleway APIs with role embedded in URL path",
			},
			{
				Pattern:         "role/[^/]+/gateway/.*",
				Handler:         b.handleGatewayStreaming,
				HelpSynopsis:    "Scaleway Transparent Gateway proxy",
				HelpDescription: "Proxies requests to Scaleway APIs with role embedded in URL path",
			},
		},
		TransparentConfig: &framework.TransparentConfig{
			AutoAuthPath:    "",
			DefaultAuthRole: "",
		},
		Backend: &framework.Backend{
			Help:           scalewayBackendHelp,
			BackendType:    "scaleway",
			BackendClass:   logical.ClassProvider,
			TokenExtractor: extractToken,
			Paths:          b.paths(),
		},
	}

	b.Logger = conf.Logger.WithSubsystem("scaleway")
	b.StorageView = conf.StorageView

	initTransport()
	b.StreamingBackend.InitProxy(sharedTransport)

	if conf.RegisterShutdownHook != nil {
		conf.RegisterShutdownHook("scaleway-transport", ShutdownHTTPTransport)
	}

	if err := b.StreamingBackend.Setup(ctx, conf); err != nil {
		return nil, err
	}

	if len(conf.Config) > 0 {
		if err := ValidateConfig(conf.Config); err != nil {
			return nil, fmt.Errorf("invalid configuration: %w", err)
		}
		parsedConfig := parseConfig(conf.Config)
		b.scalewayURL = parsedConfig.ScalewayURL
		b.MaxBodySize = parsedConfig.MaxBodySize
		b.Timeout = parsedConfig.Timeout
	}

	if b.MaxBodySize <= 0 {
		b.MaxBodySize = framework.DefaultMaxBodySize
	}
	if b.Timeout <= 0 {
		b.Timeout = DefaultScalewayTimeout
	}

	return b, nil
}

// Initialize loads persisted config from storage
func (b *scalewayBackend) Initialize(ctx context.Context) error {
	if b.StorageView == nil {
		return nil
	}

	entry, err := b.StorageView.Get(ctx, "config")
	if err != nil {
		return fmt.Errorf("failed to read config from storage: %w", err)
	}
	if entry != nil {
		var config struct {
			ScalewayURL     string `json:"scaleway_url"`
			MaxBodySize     int64  `json:"max_body_size"`
			Timeout         string `json:"timeout"`
			AutoAuthPath    string `json:"auto_auth_path"`
			DefaultAuthRole string `json:"default_role"`
		}
		if err := entry.DecodeJSON(&config); err != nil {
			return fmt.Errorf("failed to decode config: %w", err)
		}
		if config.ScalewayURL != "" {
			b.scalewayURL = config.ScalewayURL
		}
		b.MaxBodySize = config.MaxBodySize
		if config.Timeout != "" {
			if timeout, err := time.ParseDuration(config.Timeout); err == nil {
				b.Timeout = timeout
			}
		}

		b.StreamingBackend.SetTransparentConfig(&framework.TransparentConfig{
			AutoAuthPath:    config.AutoAuthPath,
			DefaultAuthRole: config.DefaultAuthRole,
		})
	}
	return nil
}

// paths returns the configuration paths for the Scaleway provider
func (b *scalewayBackend) paths() []*framework.Path {
	return []*framework.Path{
		b.pathConfig(),
	}
}

// handleGatewayStreaming wraps handleGateway for the streaming path handler
func (b *scalewayBackend) handleGatewayStreaming(ctx context.Context, req *logical.Request, fd *framework.FieldData) error {
	b.handleGateway(ctx, req)
	return nil
}

// SensitiveConfigFields returns the list of config fields that should be masked in output
func (b *scalewayBackend) SensitiveConfigFields() []string {
	return []string{}
}

const scalewayBackendHelp = `
The Scaleway provider enables proxying requests to Scaleway APIs with automatic
credential management and dual authentication mode support.

The provider auto-detects the request type based on the Authorization header:
- Standard API requests: injects X-Auth-Token header with the Scaleway secret key
  and forwards to the configured scaleway_url (default: https://api.scaleway.com)
- S3 Object Storage requests (AWS SigV4): verifies the incoming signature, re-signs
  with real Scaleway credentials, and forwards to s3.{region}.scw.cloud

The gateway path format is:
  /scaleway/gateway/{api-path}

The role can be provided via the X-Warden-Role header, or embedded in
the URL path:
  /scaleway/role/{role}/gateway/{api-path}

Standard API examples:
  /scaleway/role/{role}/gateway/instance/v1/zones/fr-par-1/servers
  /scaleway/role/{role}/gateway/k8s/v1/regions/fr-par/clusters
  /scaleway/role/{role}/gateway/rdb/v1/regions/fr-par/instances
  /scaleway/role/{role}/gateway/iam/v1alpha1/api-keys
  /scaleway/role/{role}/gateway/lb/v1/zones/fr-par-1/lbs
  /scaleway/role/{role}/gateway/registry/v1/regions/fr-par/namespaces

S3 Object Storage:
  Clients sign requests with SigV4 using their Warden JWT (as both
  aws_access_key_id and aws_secret_access_key) or role name (cert auth).
  Warden verifies the signature, re-signs with real Scaleway keys, and
  forwards to the regional S3 endpoint.

  Supported S3 regions: fr-par, nl-ams, pl-waw, it-mil

Three credential source types are supported:
- scaleway (static_keys): Static API keys stored on the spec
- scaleway (dynamic_keys): Ephemeral API keys minted via the IAM API
  (POST /iam/v1alpha1/api-keys) with automatic revocation on lease expiry.
  The management key supports automatic rotation.
- hvault (static_scaleway): Keys fetched from a Vault/OpenBao KV v2 secret

Configuration:
- scaleway_url: Scaleway API base URL (default: https://api.scaleway.com)
- max_body_size: Maximum request body size (default: 10MB, max: 100MB)
- timeout: Request timeout duration (default: 30s)
- auto_auth_path: Auth mount path for implicit authentication (e.g., 'auth/jwt/')
- default_role: Fallback role when not specified in the URL path
`
