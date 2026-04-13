package ovh

import (
	"fmt"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/provider/dualgateway"
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
		HeaderName:         "Authorization",
		HeaderValueFormat:  "Bearer %s",
		CredentialField:    "api_token",
		StripAuthorization: true,
	},

	S3Endpoint: func(_ map[string]any, region string) string {
		return fmt.Sprintf("s3.%s.io.cloud.ovh.net", region)
	},
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
  with real OVH S3 credentials, and forwards to s3.{region}.io.cloud.ovh.net

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

Credential source: ovh (OAuth2 service account)
  Warden automatically mints bearer tokens via client_credentials grant
  (~1h TTL, auto-refreshed) and creates S3 credentials on demand.

  Mint methods:
  - oauth2_token: Mints API bearer tokens only
  - dynamic_s3: Creates S3 access_key + secret_key (~1h TTL, revocable)
  - oauth2_token_and_s3: Both API token + S3 credentials

  Source config: client_id, client_secret, ovh_endpoint (ovh-eu/ovh-ca/ovh-us),
  project_id, user_id (for S3). project_id and user_id can be overridden per-spec.

Regional API endpoints and their matching OAuth2 token URLs:
- EU:  ovh_url=https://eu.api.ovh.com/1.0   token_url=https://www.ovh.com/auth/oauth2/token
- CA:  ovh_url=https://ca.api.ovh.com/1.0   token_url=https://ca.ovh.com/auth/oauth2/token
- US:  ovh_url=https://api.us.ovhcloud.com/1.0  token_url=https://us.ovhcloud.com/auth/oauth2/token

Configuration:
- ovh_url: OVH API base URL (default: https://eu.api.ovh.com/1.0)
- max_body_size: Maximum request body size (default: 10MB, max: 100MB)
- timeout: Request timeout duration (default: 30s)
- auto_auth_path: Auth mount path for implicit authentication (e.g., 'auth/jwt/')
- default_role: Fallback role when not specified in the URL path
`
