package aws

import (
	"context"
	"fmt"
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
	logger            logger.Logger
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

func (p *AWSProvider) setupRouter() {
	r := chi.NewRouter()

	r.Route("/", func(traffic chi.Router) {
		traffic.HandleFunc("/gateway*", p.handleGateway)
	})

	p.router = r
}

type AWSProviderFactory struct {
	logger logger.Logger
}

func (f *AWSProviderFactory) Type() string {
	return "aws"
}

func (f *AWSProviderFactory) Class() string {
	return "provider"
}

func (f *AWSProviderFactory) Initialize(log logger.Logger) error {
	f.logger = log.WithSubsystem(f.Type())

	return nil
}

func (f *AWSProviderFactory) Create(
	ctx context.Context,
	mountPath string,
	description string,
	accessor string,
	conf map[string]any,
	log logger.Logger,
	tokenAccess token.TokenAccess,
	roles *authorize.RoleRegistry,
	credSources *cred.CredSourceRegistry,
	auditAccess audit.AuditAccess,
) (logical.Backend, error) {

	config := parseConfig(conf)

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
		proxyDomains:  config.ProxyDomains,
		maxBodySize:   config.MaxBodySize,
		timeout:       config.Timeout,
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

	provider.initializeProcessors()

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
