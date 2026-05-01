package scaleway

import (
	"fmt"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/provider/sdk/dualgateway"
)

// Spec defines the Scaleway dual-mode gateway provider.
var Spec = &dualgateway.ProviderSpec{
	Name:           "scaleway",
	HelpText:       scalewayBackendHelp,
	CredentialType: credential.TypeScalewayKeys,

	DefaultURL:     "https://api.scaleway.com",
	URLConfigKey:   "scaleway_url",
	DefaultTimeout: 30 * time.Second,
	UserAgent:      "warden-scaleway-proxy",

	APIAuth: dualgateway.APIAuthStrategy{
		HeaderName:        "X-Auth-Token",
		HeaderValueFormat: "%s",
		CredentialField:   "secret_key",
	},

	S3Endpoint: func(_ map[string]any, region string) string {
		return fmt.Sprintf("s3.%s.scw.cloud", region)
	},
}

// Factory creates a new Scaleway provider backend.
var Factory = dualgateway.NewFactory(Spec)

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
