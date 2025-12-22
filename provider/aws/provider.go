package aws

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"net/http/httputil"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/go-chi/chi"
	"github.com/stephnangue/warden/audit"
	"github.com/stephnangue/warden/auth/token"
	"github.com/stephnangue/warden/authorize"
	"github.com/stephnangue/warden/cred"
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

type AWSProvider struct {
	mountPath         string
	description       string
	logger            *logger.GatedLogger
	accessor          string
	providerType      string
	backendClass      string
	router            *chi.Mux
	tokenAccess       token.TokenAccess
	roles             *authorize.RoleRegistry
	credSources       *cred.CredSourceRegistry
	proxy             *httputil.ReverseProxy
	signer            *v4.Signer
	proxyDomains      []string
	maxBodySize       int64
	timeout           time.Duration
	credsProvider     *cred.CredentialProvider
	processorRegistry *processor.ProcessorRegistry
	auditAccess       audit.AuditAccess
	validationFunc    func(config map[string]any) error
}

func (p *AWSProvider) GetType() string {
	return p.providerType
}

func (p *AWSProvider) GetClass() string {
	return p.backendClass
}

func (p *AWSProvider) GetDescription() string {
	return p.description
}

func (p *AWSProvider) GetAccessor() string {
	return p.accessor
}

func (p *AWSProvider) Cleanup() {
	p.credsProvider.Stop()
}

func (p *AWSProvider) Config() map[string]any {
	return map[string]any{
		"proxy_domains": p.proxyDomains,
		"max_body_size": p.maxBodySize,
		"timeout":       p.timeout.String(),
	}
}

func (p *AWSProvider) Setup(conf map[string]any) error {
	// Build current configuration
	currentConfig := map[string]interface{}{
		"proxy_domains": p.proxyDomains,
		"max_body_size": p.maxBodySize,
		"timeout":       p.timeout,
	}

	// Merge incoming config with current config (incoming takes precedence)
	mergedConfig := make(map[string]any)
	maps.Copy(mergedConfig, currentConfig)
	maps.Copy(mergedConfig, conf)

	// Validate the merged configuration using the factory's validation function
	if p.validationFunc != nil {
		if err := p.validationFunc(mergedConfig); err != nil {
			p.logger.Warn("config validation failed",
				logger.Err(err),
			)
			return err
		}
	}

	// Parse and apply the merged configuration
	newConfig := parseConfig(mergedConfig)

	// Update provider configuration
	p.proxyDomains = newConfig.ProxyDomains
	p.maxBodySize = newConfig.MaxBodySize
	p.timeout = newConfig.Timeout

	// Re-initialize processors with new proxy domains
	p.initializeProcessors()

	p.logger.Info("provider configuration updated",
		logger.Any("proxy_domains", p.proxyDomains),
		logger.Int64("max_body_size", p.maxBodySize),
		logger.String("timeout", p.timeout.String()),
	)
	return nil
}

func (p *AWSProvider) setupRouter() {
	r := chi.NewRouter()

	r.Route("/", func(traffic chi.Router) {
		traffic.HandleFunc("/gateway*", p.handleGateway)
	})

	p.router = r
}

type AWSProviderFactory struct {
	logger *logger.GatedLogger
}

func (f *AWSProviderFactory) Type() string {
	return "aws"
}

func (f *AWSProviderFactory) Class() string {
	return "provider"
}

func (f *AWSProviderFactory) Initialize(log *logger.GatedLogger) error {
	f.logger = log.WithSubsystem(f.Type())

	return nil
}

// ValidateConfig validates AWS provider-specific configuration
func (f *AWSProviderFactory) ValidateConfig(config map[string]any) error {
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
		default:
			return fmt.Errorf("max_body_size must be an integer")
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

func (f *AWSProviderFactory) Create(
	ctx context.Context,
	mountPath string,
	description string,
	accessor string,
	conf map[string]any,
	log *logger.GatedLogger,
	tokenAccess token.TokenAccess,
	roles *authorize.RoleRegistry,
	credSources *cred.CredSourceRegistry,
	auditAccess audit.AuditAccess,
) (logical.Backend, error) {

	credsProvider, err := cred.NewCredentialProvider(roles, credSources, log.WithSubsystem("aws").WithSubsystem("cred"))
	if err != nil {
		return nil, err
	}

	provider := &AWSProvider{
		mountPath:     mountPath,
		description:   description,
		accessor:      accessor,
		logger:        log.WithSubsystem(f.Type()).WithSubsystem(accessor),
		providerType:  f.Type(),
		backendClass:  f.Class(),
		tokenAccess:   tokenAccess,
		roles:         roles,
		credSources:   credSources,
		signer:        v4.NewSigner(),
		credsProvider: credsProvider,
		auditAccess:   auditAccess,
	}

	provider.setupRouter()

	provider.proxy = &httputil.ReverseProxy{
		Director: func(req *http.Request) {

		},
		Transport: sharedTransport,
		ModifyResponse: func(resp *http.Response) error {
			// Extract context information stored during request processing
			ctx := resp.Request.Context()

			// // Retrieve all stored values from context (with type assertions)
			clientToken, _ := ctx.Value(ClientTokenKey).(*audit.Token)
			awsCreds, _ := ctx.Value(AWSCredsKey).(aws.Credentials)
			token, _ := ctx.Value(TokenKey).(*token.Token)
			roleName, _ := ctx.Value(RoleNameKey).(string)
			principalID, _ := ctx.Value(PrincipalIDKey).(string)
			targetURL, _ := ctx.Value(TargetURLKey).(string)
			service, _ := ctx.Value(ServiceKey).(string)
			region, _ := ctx.Value(RegionKey).(string)

			// Build metadata
			metadata := map[string]interface{}{
				"service": service,
				"region":  region,
			}

			// Determine status message based on status code
			var message string
			if resp.StatusCode >= 400 {
				message = "Request failed"
			} else {
				message = "Request successful"
			}

			// // Audit the response with all context information
			ok := provider.auditResponse(resp, resp.Request, clientToken, &awsCreds, token, roleName, principalID,
				resp.StatusCode, message, "", targetURL, metadata)
			if !ok {
				return fmt.Errorf("failed to audit response")
			}

			return nil
		},
	}

	provider.validationFunc = f.ValidateConfig

	// err = provider.Setup(conf)
	// if err != nil {
	// 	return nil, err
	// }

	return provider, nil
}

func (p *AWSProvider) initializeProcessors() {
	p.processorRegistry = processor.NewProcessorRegistry()

	// Register processors
	p.processorRegistry.Register(s3.NewS3AccessPointProcessor(p.proxyDomains, p.logger))
	p.processorRegistry.Register(s3.NewS3ControlProcessor(p.proxyDomains, p.logger))
	p.processorRegistry.Register(s3.NewS3Processor(p.proxyDomains, p.logger))
	p.processorRegistry.Register(processor.NewGenericAWSProcessor(p.proxyDomains, p.logger))
}
