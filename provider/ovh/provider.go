package ovh

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/provider/sdk/dualgateway"
)

// Spec defines the OVH dual-mode gateway provider.
var Spec = &dualgateway.ProviderSpec{
	Name:           "ovh",
	HelpText:       ovhBackendHelp,
	CredentialType: credential.TypeOVHKeys,

	DefaultURL:     "https://eu.api.ovh.com/1.0",
	URLConfigKey:   "ovh_url",
	DefaultTimeout: 30 * time.Second,
	UserAgent:      "warden-ovh-proxy",

	APIAuth: dualgateway.APIAuthStrategy{
		HeaderName:        "Authorization",
		HeaderValueFormat: "Bearer %s",
		CredentialField:   "api_token",
	},

	ExtraConfigKeys: []string{"s3_url"},
	ExtraConfigFields: map[string]*framework.FieldSchema{
		"s3_url": {
			Type:        framework.TypeString,
			Description: "Override the Object Storage host the region would resolve to, for a private egress gateway fronting it. Host or URL; the S3 leg is always https.",
		},
	},
	ValidateExtraConfig: func(config map[string]any) error {
		// Nothing else checks this key, so a typo would be stored happily and
		// surface much later as a per-request failure against a nonsense host.
		configured := framework.GetConfigString(config, "s3_url", "")
		if configured == "" {
			return nil
		}
		host := s3Host(configured)
		if host == "" || strings.ContainsAny(host, "/?#") {
			return fmt.Errorf("s3_url must name a host, optionally with a port: %q", configured)
		}
		return nil
	},
	// Keyed as the operator wrote it, so a config read reports something the
	// config write would accept. A host is itself a valid s3_url.
	OnConfigParsed: func(config map[string]any) map[string]any {
		return map[string]any{
			"s3_url": s3Host(framework.GetConfigString(config, "s3_url", "")),
		}
	},
	S3Endpoint: func(state map[string]any, region string) string {
		// The same reason ovh_url exists on the API side: an operator whose
		// traffic leaves through a private gateway needs to name it. Without
		// this the region is the only answer and the S3 leg always addresses
		// the public host.
		if host, _ := state["s3_url"].(string); host != "" {
			return host
		}
		return fmt.Sprintf("s3.%s.io.cloud.ovh.net", region)
	},
}

// s3Host reduces an operator-set s3_url to the host S3Endpoint must return.
// A URL is accepted because that is what the API-side key takes and operators
// will write one either way; the scheme is dropped rather than honoured, since
// the S3 leg re-signs and forwards over https regardless.
func s3Host(configured string) string {
	if configured == "" {
		return ""
	}
	if parsed, err := url.Parse(configured); err == nil && parsed.Host != "" {
		return parsed.Host
	}
	return strings.TrimSuffix(configured, "/")
}

// Factory creates a new OVH provider backend.
var Factory = dualgateway.NewFactory(Spec)

const ovhBackendHelp = `
The OVH provider enables proxying requests to OVHcloud APIs with automatic
credential management and dual authentication mode support.

The provider auto-detects the request type based on the Authorization header:
- Standard API requests: injects Authorization: Bearer header with the API
  token and forwards to the configured ovh_url (default: https://eu.api.ovh.com/1.0)
- S3 Object Storage requests (AWS SigV4): verifies the incoming signature, re-signs
  with real OVH S3 credentials, and forwards to s3.{region}.io.cloud.ovh.net,
  or to s3_url when one is set

The gateway path format is:
  /ovh/gateway/{api-path}

The role can be provided via the X-Warden-Role header, or embedded in
the URL path:
  /ovh/role/{role}/gateway/{api-path}

Standard API examples:
  /ovh/role/{role}/gateway/me
  /ovh/role/{role}/gateway/cloud/project
  /ovh/role/{role}/gateway/domain
  /ovh/role/{role}/gateway/ip

S3 Object Storage:
  Clients sign requests with SigV4 using their Warden JWT (as both
  aws_access_key_id and aws_secret_access_key) or role name (cert auth).
  Warden verifies the signature, re-signs with real OVH S3 keys, and
  forwards to the regional S3 endpoint.

  S3 regions: gra, bhs, sbg, de, uk, waw

Credential type: ovh_keys
  - api_token: API bearer token for the REST API
  - access_key: S3 access key for Object Storage
  - secret_key: S3 secret key for Object Storage

Credential source: ovh
  Mint methods:
  - oauth2_token: Mints an API bearer token via the client_credentials grant,
    using the service account in the source config (auto-refreshed).
  - access_keys: Serves the Object Storage access_key + secret_key a referenced
    spec yields. The spec sets secret_spec naming that reference; the pair is
    read from it per request and nothing is created at OVH.

  A spec serves one mode, so a role fronting both the REST API and Object
  Storage needs one spec of each.

  Source config: client_id, client_secret (both required only for oauth2_token
  specs), ovh_endpoint (ovh-eu/ovh-ca/ovh-us), token_url. Set secret_spec
  instead of the pair to fetch the service account per request, so the source
  stores no credential of its own.

Regional API endpoints and their matching OAuth2 token URLs:
- EU:  ovh_url=https://eu.api.ovh.com/1.0   token_url=https://www.ovh.com/auth/oauth2/token
- CA:  ovh_url=https://ca.api.ovh.com/1.0   token_url=https://ca.ovh.com/auth/oauth2/token
- US:  ovh_url=https://api.us.ovhcloud.com/1.0  token_url=https://us.ovhcloud.com/auth/oauth2/token

Configuration:
- ovh_url: OVH API base URL (default: https://eu.api.ovh.com/1.0)
- s3_url: Object Storage host override (default: s3.{region}.io.cloud.ovh.net)
- max_body_size: Maximum request body size (default: 10MB, max: 100MB)
- timeout: Request timeout duration (default: 30s)
- auto_auth_path: Auth mount path for implicit authentication (e.g., 'auth/jwt/')
- default_role: Fallback role when not specified in the URL path
`
