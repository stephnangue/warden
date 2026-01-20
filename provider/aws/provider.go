package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"time"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/aws/processor"
	"github.com/stephnangue/warden/provider/aws/processor/s3"
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
	logger            *logger.GatedLogger
	proxy             *httputil.ReverseProxy
	signer            *v4.Signer
	s3Signer          *v4.Signer // Signer for S3/S3-Control with DisableURIPathEscaping
	proxyDomains      []string
	maxBodySize       int64
	timeout           time.Duration
	processorRegistry *processor.ProcessorRegistry
	storageView       sdklogical.Storage
	cleanedUp         bool
}

// extractToken extracts Access Key ID from AWS SigV4 Authorization header
func extractToken(r *http.Request) string {
	// Format: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20231215/...
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "AWS4-HMAC-SHA256") {
		return ""
	}
	return extractAccessKeyID(authHeader)
}

// extractAccessKeyID extracts the Access Key ID from an AWS SigV4 Authorization header.
// Format: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20231215/us-east-1/s3/aws4_request
func extractAccessKeyID(authHeader string) string {
	const prefix = "Credential="
	idx := strings.Index(authHeader, prefix)
	if idx == -1 {
		return ""
	}

	start := idx + len(prefix)
	if start >= len(authHeader) {
		return ""
	}

	end := strings.IndexByte(authHeader[start:], '/')
	if end == -1 {
		return ""
	}

	return authHeader[start : start+end]
}

// Factory creates a new AWS provider backend using the logical.Factory pattern
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &awsBackend{
		logger:      conf.Logger.WithSubsystem("aws"),
		signer:      v4.NewSigner(),
		storageView: conf.StorageView,
		// S3 and S3-Control services require DisableURIPathEscaping because
		// AWS SDKs sign these requests without additional path escaping.
		// Without this, paths with special characters (like ARNs with colons)
		// will have signature mismatches due to double-encoding.
		s3Signer: v4.NewSigner(func(o *v4.SignerOptions) {
			o.DisableURIPathEscaping = true
		}),
	}

	// Initialize proxy
	// Note: Director is intentionally empty because we modify req.HTTPRequest directly
	// in processRequest before calling ServeHTTP. The ReverseProxy will use the
	// already-modified request URL, Host, and headers.
	b.proxy = &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			// Request is already prepared by processRequest - nothing to do here
			// The URL, Host, and headers have been set before ServeHTTP is called
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
		Backend: &framework.Backend{
			Help:           awsBackendHelp,
			BackendType:    "aws",
			BackendClass:   logical.ClassProvider,
			TokenExtractor: extractToken,
			Paths:          b.paths(),
		},
	}

	// Apply configuration if provided
	if len(conf.Config) > 0 {
		if err := ValidateConfig(conf.Config); err != nil {
			return nil, fmt.Errorf("invalid configuration: %w", err)
		}
		parsedConfig := parseConfig(conf.Config)
		b.proxyDomains = parsedConfig.ProxyDomains
		b.maxBodySize = parsedConfig.MaxBodySize
		b.timeout = parsedConfig.Timeout
		b.initializeProcessors()
	}

	return b, nil
}

// Initialize loads persisted config from storage
func (b *awsBackend) Initialize(ctx context.Context) error {
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
			ProxyDomains []string `json:"proxy_domains"`
			MaxBodySize  int64    `json:"max_body_size"`
			Timeout      string   `json:"timeout"`
		}
		if err := entry.DecodeJSON(&config); err != nil {
			return fmt.Errorf("failed to decode config: %w", err)
		}
		b.proxyDomains = config.ProxyDomains
		b.maxBodySize = config.MaxBodySize
		if config.Timeout != "" {
			if timeout, err := time.ParseDuration(config.Timeout); err == nil {
				b.timeout = timeout
			}
		}
		b.initializeProcessors()
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
	b.processorRegistry.Register(s3.NewS3AccessPointProcessor(b.proxyDomains, b.logger))
	b.processorRegistry.Register(s3.NewS3ControlProcessor(b.proxyDomains, b.logger))
	b.processorRegistry.Register(s3.NewS3Processor(b.proxyDomains, b.logger))
	b.processorRegistry.Register(processor.NewGenericAWSProcessor(b.proxyDomains, b.logger))
}

// ValidateConfig validates AWS provider-specific configuration
func ValidateConfig(config map[string]any) error {
	allowedKeys := map[string]bool{
		"proxy_domains": true,
		"max_body_size": true,
		"timeout":       true,
	}

	// Check for unknown keys
	for key := range config {
		if !allowedKeys[key] {
			return fmt.Errorf("unknown configuration key: %s (allowed: proxy_domains, max_body_size, timeout)", key)
		}
	}

	// Validate proxy_domains
	if domains, ok := config["proxy_domains"]; ok {
		switch v := domains.(type) {
		case []any:
			for i, d := range v {
				if _, ok := d.(string); !ok {
					return fmt.Errorf("proxy_domains[%d] must be a string", i)
				}
			}
		case []string:
		default:
			return fmt.Errorf("proxy_domains must be an array of strings")
		}
	}

	// Validate max_body_size
	if maxSize, ok := config["max_body_size"]; ok {
		var size int64
		switch v := maxSize.(type) {
		case int:
			size = int64(v)
		case int64:
			size = v
		case float64:
			size = int64(v)
		case json.Number:
			parsed, err := v.Int64()
			if err != nil {
				return fmt.Errorf("max_body_size must be an integer, got json.Number that can't be parsed: %w", err)
			}
			size = parsed
		case string:
			parsed, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return fmt.Errorf("max_body_size must be an integer, got string that can't be parsed: %w", err)
			}
			size = parsed
		default:
			return fmt.Errorf("max_body_size must be an integer, got %T", maxSize)
		}
		if size < 0 {
			return fmt.Errorf("max_body_size must be greater than 0")
		}
		if size > 104857600 { // 100MB
			return fmt.Errorf("max_body_size must not exceed 104857600 bytes (100MB)")
		}
	}

	// Validate timeout
	if timeout, ok := config["timeout"]; ok {
		switch v := timeout.(type) {
		case string:
			if _, err := time.ParseDuration(v); err != nil {
				return fmt.Errorf("invalid timeout format: %w (expected format: '30s', '5m', '1h')", err)
			}
		case int:
			if v < 0 {
				return fmt.Errorf("timeout must be greater than 0 seconds")
			}
		case float64:
			if v < 0 {
				return fmt.Errorf("timeout must be greater than 0 seconds")
			}
		default:
			return fmt.Errorf("timeout must be a duration string (e.g., '30s') or integer (seconds)")
		}
	}

	return nil
}

// SensitiveConfigFields returns the list of config fields that should be masked in output
func (b *awsBackend) SensitiveConfigFields() []string {
	// AWS provider doesn't store credentials in config - uses credential minting from specs
	return []string{}
}

const awsBackendHelp = `
The AWS provider enables proxying requests to AWS services with automatic
credential management and signature conversion.

Requests to the gateway/ path are proxied to AWS with the appropriate
SigV4 signature applied.
`
