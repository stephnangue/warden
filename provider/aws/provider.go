package aws

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/aws/processor"
	"github.com/stephnangue/warden/provider/aws/processor/s3"
	"github.com/stephnangue/warden/provider/sigv4"
)

// HostRewrite contains information about a rewritten virtual-hosted URL
type HostRewrite struct {
	Service string // The AWS service (s3, dynamodb, etc.)
	Prefix  string // The prefix extracted from hostname (bucket name, etc.)
	Region  string // The region if extracted from hostname
}

// awsBackend is the streaming backend for AWS provider operations
type awsBackend struct {
	*framework.StreamingBackend
	signer            *v4.Signer
	s3Signer          *v4.Signer // Signer for S3/S3-Control with DisableURIPathEscaping
	proxyDomains      []string
	processorRegistry *processor.ProcessorRegistry
	tlsSkipVerify     bool
	caData            string
}

// extractToken extracts the client token from the request.
// Handles two implicit auth modes:
//   - JWT transparent: JWT in X-Amz-Security-Token (core detects "eyJ" prefix)
//   - Cert transparent: access_key_id (role name) from SigV4 header
func extractToken(r *http.Request) string {
	// JWT auth: JWT in X-Amz-Security-Token
	if secToken := r.Header.Get("X-Amz-Security-Token"); strings.HasPrefix(secToken, "eyJ") {
		return secToken
	}
	// Cert transparent: access_key_id (role name) from SigV4 header
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "AWS4-HMAC-SHA256") {
		return ""
	}
	return sigv4.ExtractAccessKeyID(authHeader)
}

// Compile-time interface assertion
var _ logical.TransparentAuthRoleExtractor = (*awsBackend)(nil)

// GetAuthRoleFromRequest extracts the auth role from the SigV4 Authorization header.
// Returns (role, true) when access_key_id is present (used as the role name).
// Returns ("", false) when no Authorization header is present.
func (b *awsBackend) GetAuthRoleFromRequest(r *http.Request) (string, bool) {
	accessKeyID := sigv4.ExtractAccessKeyID(r.Header.Get("Authorization"))
	if accessKeyID == "" {
		return "", false
	}
	return accessKeyID, true
}

// Factory creates a new AWS provider backend using the logical.Factory pattern
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &awsBackend{
		signer: v4.NewSigner(),
		// S3 and S3-Control services require DisableURIPathEscaping because
		// AWS SDKs sign these requests without additional path escaping.
		// Without this, paths with special characters (like ARNs with colons)
		// will have signature mismatches due to double-encoding.
		s3Signer: v4.NewSigner(func(o *v4.SignerOptions) {
			o.DisableURIPathEscaping = true
		}),
	}

	// Create the streaming backend with gateway path for streaming
	b.StreamingBackend = &framework.StreamingBackend{
		StreamingPaths: []*framework.StreamingPath{
			{
				Pattern:         "gateway",
				Handler:         b.handleGatewayStreaming,
				HelpSynopsis:    "AWS Gateway proxy",
				HelpDescription: "Proxies requests to AWS services with signature verification",
			},
			{
				Pattern:         "gateway/.*",
				Handler:         b.handleGatewayStreaming,
				HelpSynopsis:    "AWS Gateway proxy",
				HelpDescription: "Proxies requests to AWS services with signature verification",
			},
		},
		TransparentConfig: &framework.TransparentConfig{
			AutoAuthPath:    "",
			DefaultAuthRole: "",
		},
		Backend: &framework.Backend{
			Help:           awsBackendHelp,
			BackendType:    "aws",
			BackendClass:   logical.ClassProvider,
			TokenExtractor: extractToken,
			Paths:          b.paths(),
		},
	}

	// Set common fields
	b.Logger = conf.Logger.WithSubsystem("aws")
	b.StorageView = conf.StorageView

	// Initialize reverse proxy with AWS transport (lazily created on first use)
	initTransport()
	b.StreamingBackend.InitProxy(sharedTransport)

	// Register transport shutdown hook for process-level cleanup
	if conf.RegisterShutdownHook != nil {
		conf.RegisterShutdownHook("aws-transport", ShutdownHTTPTransport)
	}

	if err := b.StreamingBackend.Setup(ctx, conf); err != nil {
		return nil, err
	}

	// Apply configuration if provided
	if len(conf.Config) > 0 {
		if err := ValidateConfig(conf.Config); err != nil {
			return nil, fmt.Errorf("invalid configuration: %w", err)
		}
		parsedConfig := parseConfig(conf.Config)
		b.proxyDomains = parsedConfig.ProxyDomains
		b.MaxBodySize = parsedConfig.MaxBodySize
		b.Timeout = parsedConfig.Timeout
		b.tlsSkipVerify = parsedConfig.TLSSkipVerify
		b.caData = parsedConfig.CAData
		b.initializeProcessors()

		// Update transport if custom TLS config is set
		if b.tlsSkipVerify || b.caData != "" {
			transport, err := newTransportWithTLS(b.caData, b.tlsSkipVerify)
			if err != nil {
				return nil, fmt.Errorf("invalid TLS configuration: %w", err)
			}
			b.Proxy.Transport = transport
		}
	}

	// Ensure defaults are set even when no config is provided
	if b.MaxBodySize <= 0 {
		b.MaxBodySize = framework.DefaultMaxBodySize
	}
	if b.Timeout <= 0 {
		b.Timeout = framework.DefaultTimeout
	}

	return b, nil
}

// Initialize loads persisted config from storage
func (b *awsBackend) Initialize(ctx context.Context) error {
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
			ProxyDomains    []string `json:"proxy_domains"`
			MaxBodySize     int64    `json:"max_body_size"`
			Timeout         string   `json:"timeout"`
			TLSSkipVerify   bool     `json:"tls_skip_verify"`
			CAData          string   `json:"ca_data"`
			AutoAuthPath    string   `json:"auto_auth_path"`
			DefaultAuthRole string   `json:"default_role"`
		}
		if err := entry.DecodeJSON(&config); err != nil {
			return fmt.Errorf("failed to decode config: %w", err)
		}
		b.proxyDomains = config.ProxyDomains
		b.MaxBodySize = config.MaxBodySize
		b.tlsSkipVerify = config.TLSSkipVerify
		b.caData = config.CAData
		if config.Timeout != "" {
			if timeout, err := time.ParseDuration(config.Timeout); err == nil {
				b.Timeout = timeout
			}
		}
		b.initializeProcessors()

		// Update transport if custom TLS config is set
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
	}
	return nil
}

// paths returns the configuration paths for the AWS provider
func (b *awsBackend) paths() []*framework.Path {
	return []*framework.Path{
		b.pathConfig(),
	}
}

// handleGatewayStreaming handles streaming gateway requests
func (b *awsBackend) handleGatewayStreaming(ctx context.Context, req *logical.Request, fd *framework.FieldData) error {
	b.handleGateway(ctx, req)
	return nil
}

func (b *awsBackend) initializeProcessors() {
	b.processorRegistry = processor.NewProcessorRegistry()

	// Register processors
	b.processorRegistry.Register(s3.NewS3AccessPointProcessor(b.proxyDomains, b.Logger))
	b.processorRegistry.Register(s3.NewS3ControlProcessor(b.proxyDomains, b.Logger))
	b.processorRegistry.Register(s3.NewS3Processor(b.proxyDomains, b.Logger))
	b.processorRegistry.Register(processor.NewGenericAWSProcessor(b.proxyDomains, b.Logger))
}

// SensitiveConfigFields returns the list of config fields that should be masked in output
func (b *awsBackend) SensitiveConfigFields() []string {
	return []string{"ca_data"}
}

const awsBackendHelp = `
The AWS provider enables proxying requests to AWS services with automatic
credential management and SigV4 signature conversion.

Clients sign requests with their Warden-issued AWS access keys. The provider
verifies the incoming signature, re-signs the request with real AWS credentials
from the credential manager, and proxies it to the target AWS service. This
allows Warden to broker access without exposing real AWS credentials to clients.

The gateway path format is:
  /aws/gateway

Clients set the Host header or URL to the target AWS endpoint; the provider
reads the service and region from the SigV4 Authorization header.

Examples:
  PUT /aws/gateway  (Host: my-bucket.s3.us-east-1.amazonaws.com)
  POST /aws/gateway (Host: dynamodb.us-east-1.amazonaws.com)
  GET /aws/gateway  (Host: sts.amazonaws.com)

Service-specific processors handle URL rewriting for virtual-hosted S3 buckets,
S3-Control ARN paths, and other services that require special treatment.

Configuration:
- proxy_domains: Allowlist of permitted AWS service domains
- max_body_size: Maximum request body size (default: 10MB, max: 100MB)
- timeout: Request timeout duration (e.g., '30s', '5m')
`
