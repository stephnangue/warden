package cloudflare

import (
	"fmt"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/sdk/dualgateway"
)

// DefaultCloudflareURL is the default Cloudflare API base URL
const DefaultCloudflareURL = "https://api.cloudflare.com/client/v4"

// DefaultCloudflareTimeout is the default request timeout for Cloudflare API calls
const DefaultCloudflareTimeout = 30 * time.Second

// Spec defines the Cloudflare dual-mode gateway provider.
var Spec = &dualgateway.ProviderSpec{
	Name:           "cloudflare",
	HelpText:       cloudflareBackendHelp,
	CredentialType: credential.TypeCloudflareKeys,

	DefaultURL:     DefaultCloudflareURL,
	URLConfigKey:   "cloudflare_url",
	DefaultTimeout: DefaultCloudflareTimeout,
	UserAgent:      "warden-cloudflare-proxy",

	APIAuth: dualgateway.APIAuthStrategy{
		HeaderName:         "Authorization",
		HeaderValueFormat:  "Bearer %s",
		CredentialField:    "api_token",
		StripAuthorization: true,
	},

	ExtraConfigKeys: []string{"account_id", "r2_jurisdiction"},
	ExtraConfigFields: map[string]*framework.FieldSchema{
		"account_id": {
			Type:        framework.TypeString,
			Description: "Cloudflare account ID (required for R2 S3 Object Storage)",
		},
		"r2_jurisdiction": {
			Type:        framework.TypeString,
			Description: "R2 jurisdiction: empty (default), 'eu', or 'fedramp'",
		},
	},
	OnConfigParsed: func(config map[string]any) map[string]any {
		return map[string]any{
			"account_id":      framework.GetConfigString(config, "account_id", ""),
			"r2_jurisdiction": framework.GetConfigString(config, "r2_jurisdiction", ""),
		}
	},
	S3Endpoint: func(state map[string]any, region string) string {
		accountID, _ := state["account_id"].(string)
		jurisdiction, _ := state["r2_jurisdiction"].(string)
		if jurisdiction != "" {
			return fmt.Sprintf("%s.%s.r2.cloudflarestorage.com", accountID, jurisdiction)
		}
		return fmt.Sprintf("%s.r2.cloudflarestorage.com", accountID)
	},

	// Override: R2 uses access_key_id/secret_access_key (not access_key/secret_key)
	ExtractS3Credentials: func(req *logical.Request) (awssdk.Credentials, error) {
		if req.Credential == nil {
			return awssdk.Credentials{}, fmt.Errorf("no credential available")
		}
		if req.Credential.Type != credential.TypeCloudflareKeys {
			return awssdk.Credentials{}, fmt.Errorf("unsupported credential type: %s", req.Credential.Type)
		}
		ak := req.Credential.Data["access_key_id"]
		sk := req.Credential.Data["secret_access_key"]
		if ak == "" || sk == "" {
			return awssdk.Credentials{}, fmt.Errorf("credential missing access_key_id or secret_access_key")
		}
		return awssdk.Credentials{AccessKeyID: ak, SecretAccessKey: sk}, nil
	},
}

// Factory creates a new Cloudflare provider backend.
var Factory = dualgateway.NewFactory(Spec)

const cloudflareBackendHelp = `
The Cloudflare provider enables proxying requests to Cloudflare APIs with
automatic credential management and dual authentication mode support.

The provider auto-detects the request type based on the Authorization header:
- Standard API requests: injects Authorization: Bearer header with the API
  token and forwards to the configured cloudflare_url (default: https://api.cloudflare.com/client/v4)
- R2 Object Storage requests (AWS SigV4): verifies the incoming signature, re-signs
  with real Cloudflare R2 credentials, and forwards to <account_id>.r2.cloudflarestorage.com

The gateway path format is:
  /cloudflare/gateway/{api-path}

The role can be provided via the X-Warden-Role header, or embedded in
the URL path:
  /cloudflare/role/{role}/gateway/{api-path}

Standard API examples:
  /cloudflare/role/{role}/gateway/zones
  /cloudflare/role/{role}/gateway/zones/{zone_id}/dns_records
  /cloudflare/role/{role}/gateway/user/tokens/verify
  /cloudflare/role/{role}/gateway/accounts/{account_id}/workers/scripts

R2 Object Storage:
  Clients sign requests with SigV4 using their Warden JWT (as both
  aws_access_key_id and aws_secret_access_key) or role name (cert auth).
  Warden verifies the signature, re-signs with real Cloudflare R2 keys, and
  forwards to the R2 endpoint.

  R2 region is always "auto" for SigV4 signing.

  R2 jurisdictions: default (empty), eu, fedramp

Credential type: cloudflare_keys (at least one mode required)
  - api_token: API bearer token for the REST API (API mode)
  - access_key_id: R2 access key ID for Object Storage (R2 mode)
  - secret_access_key: R2 secret access key for Object Storage (R2 mode)

Two credential source types are supported:
- local (static_keys): Static credentials stored on the spec
- hvault (static_cloudflare): Keys fetched from a Vault/OpenBao KV v2 secret

Configuration:
- cloudflare_url: Cloudflare API base URL (default: https://api.cloudflare.com/client/v4)
- account_id: Cloudflare account ID (required for R2 S3 Object Storage)
- r2_jurisdiction: R2 jurisdiction - empty (default), 'eu', or 'fedramp'
- max_body_size: Maximum request body size (default: 10MB, max: 100MB)
- timeout: Request timeout duration (default: 30s)
- auto_auth_path: Auth mount path for implicit authentication (e.g., 'auth/jwt/')
- default_role: Fallback role when not specified in the URL path
`
