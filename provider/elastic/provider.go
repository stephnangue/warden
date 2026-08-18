package elastic

import (
	"fmt"
	"net/http"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/sdk/httpproxy"
)

// DefaultElasticTimeout is the default request timeout for Elasticsearch API calls
const DefaultElasticTimeout = 30 * time.Second

// elasticCredentialExtractor extracts the pre-encoded API key from a TypeAPIKey
// credential and injects it as the Authorization: ApiKey header.
//
// Elasticsearch API keys use the format: Authorization: ApiKey <base64(id:api_key)>
// The credential's api_key field is expected to contain the pre-encoded base64 value
// (the "encoded" field from Elasticsearch's create API key response).
func elasticCredentialExtractor(req *logical.Request) (map[string]string, error) {
	if req.Credential == nil {
		return nil, fmt.Errorf("no credential available")
	}
	if req.Credential.Type != credential.TypeAPIKey {
		return nil, fmt.Errorf("unsupported credential type: %s", req.Credential.Type)
	}
	apiKey := req.Credential.Data["api_key"]
	if apiKey == "" {
		return nil, fmt.Errorf("credential missing api_key field")
	}
	return map[string]string{
		"Authorization": "ApiKey " + apiKey,
	}, nil
}

// extractTokens resolves the two principals on a Elasticsearch gateway request.
//
// Elasticsearch's own agent credential rides Authorization under the native
// "ApiKey" scheme, so agent and user can share the header only by dispatching
// on scheme: "ApiKey" is always the agent, "Bearer" is the user once an agent
// has arrived out of band. Precedence matches the pre-0.20 extractor when
// userLeg is false — X-Warden-Token, then ApiKey, then Bearer.
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
//	Authorization: ApiKey n             n           n          -
//	Authorization: ApiKey n + cert      n           n          -
func extractTokens(r *http.Request, userLeg bool) (agent, user string) {
	// X-Warden-Token is the operator credential and never opens the user leg.
	// See logical.ExtractTokensDefault.
	if token := r.Header.Get(logical.HeaderWardenToken); token != "" {
		return token, ""
	}
	authHeader := r.Header.Get("Authorization")

	// The native scheme is the agent's own channel. It occupies Authorization,
	// so there is no slot left for a user credential on this request.
	if token := logical.StripScheme(authHeader, "ApiKey "); token != "" {
		return token, ""
	}

	if a, ok := logical.AgentOutOfBand(r, userLeg); ok {
		return a, logical.StripBearer(authHeader)
	}
	return logical.StripBearer(authHeader), ""
}

// Spec defines the Elastic provider configuration for the httpproxy framework.
var Spec = &httpproxy.ProviderSpec{
	Name:               "elastic",
	DefaultURL:         "", // Instance-specific, must be configured
	URLConfigKey:       "elastic_url",
	DefaultTimeout:     DefaultElasticTimeout,
	ParseStreamBody:    true,
	UserAgent:          "warden-elastic-proxy",
	HelpText:           elasticBackendHelp,
	ExtractCredentials: elasticCredentialExtractor,
	ExtractToken:       extractTokens,
	ValidateExtraConfig: func(conf map[string]any) error {
		addr, ok := conf["elastic_url"].(string)
		if !ok || addr == "" {
			return fmt.Errorf("elastic_url is required")
		}
		return nil
	},
}

// Factory creates a new Elastic provider backend.
var Factory = httpproxy.NewFactory(Spec)

const elasticBackendHelp = `
The Elastic provider enables proxying requests to an Elasticsearch cluster
REST API with automatic credential management and API key injection.

Warden performs implicit authentication on every request and obtains an
Elasticsearch API key from the credential manager, injecting it into the
proxied request's Authorization header using the ApiKey scheme. This allows
Warden to broker Elasticsearch access without exposing keys to clients.

The gateway path format is:
  /elastic/gateway/{api-path}

Examples:
  /elastic/gateway/_cluster/health
  /elastic/gateway/_cat/indices
  /elastic/gateway/my-index/_search
  /elastic/gateway/_security/api_key
  /elastic/gateway/_bulk

The role can be provided via the X-Warden-Role header, or embedded in
the URL path:
  /elastic/role/{role}/gateway/{api-path}

Request body parsing is enabled, allowing policies to evaluate Elasticsearch
request fields for fine-grained access control.

Three credential source types are supported:
- apikey: Static pre-encoded API key (base64 of id:api_key, stored in spec
  config as api_key)
- elastic: Elasticsearch driver with programmatic API key creation and
  rotation via the /_security/api_key endpoint
- hvault: Vault/OpenBao KV v2 secret containing api_key; use
  mint_method=static_apikey on the spec

Configuration:
- elastic_url: Elasticsearch cluster URL (required, e.g., "https://my-cluster.es.us-east-1.aws.cloud.es.io")
- max_body_size: Maximum request body size (default: 10MB, max: 100MB)
- timeout: Request timeout duration (default: 30s)
- auto_auth_path: Auth mount path for implicit authentication (e.g., 'auth/jwt/')
- default_role: Fallback role when not specified in the URL path

The elastic_url must point to your Elasticsearch cluster endpoint. Elastic
Cloud deployments use region-specific URLs, for example:
  https://<deployment-id>.es.<region>.cloud.es.io
`
