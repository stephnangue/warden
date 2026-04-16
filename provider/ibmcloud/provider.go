package ibmcloud

import (
	"fmt"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/dualgateway"
)

// DefaultIBMCloudURL is the default IBM Cloud API base URL
const DefaultIBMCloudURL = "https://cloud.ibm.com"

// DefaultIBMCloudTimeout is the default request timeout for IBM Cloud API calls
const DefaultIBMCloudTimeout = 30 * time.Second

// Spec defines the IBM Cloud dual-mode gateway provider.
var Spec = &dualgateway.ProviderSpec{
	Name:           "ibmcloud",
	HelpText:       ibmcloudBackendHelp,
	CredentialType: credential.TypeIBMCloudKeys,

	DefaultURL:     DefaultIBMCloudURL,
	URLConfigKey:   "ibmcloud_url",
	DefaultTimeout: DefaultIBMCloudTimeout,
	UserAgent:      "warden-ibmcloud-proxy",

	APIAuth: dualgateway.APIAuthStrategy{
		HeaderName:         "Authorization",
		HeaderValueFormat:  "Bearer %s",
		CredentialField:    "access_token",
		StripAuthorization: true,
	},

	S3Endpoint: func(_ map[string]any, region string) string {
		return fmt.Sprintf("s3.%s.cloud-object-storage.appdomain.cloud", region)
	},

	// COS uses access_key_id/secret_access_key (same field names as Cloudflare R2)
	ExtractS3Credentials: func(req *logical.Request) (awssdk.Credentials, error) {
		if req.Credential == nil {
			return awssdk.Credentials{}, fmt.Errorf("no credential available")
		}
		if req.Credential.Type != credential.TypeIBMCloudKeys {
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

// Factory creates a new IBM Cloud provider backend.
var Factory = dualgateway.NewFactory(Spec)

const ibmcloudBackendHelp = `
The IBM Cloud provider enables proxying requests to IBM Cloud APIs with
automatic credential management and dual authentication mode support.

The provider auto-detects the request type based on the Authorization header:
- Standard API requests: injects Authorization: Bearer header with the IAM
  token and forwards to the configured ibmcloud_url (default: https://cloud.ibm.com)
- COS Object Storage requests (AWS SigV4): verifies the incoming signature, re-signs
  with real IBM COS HMAC credentials, and forwards to s3.{region}.cloud-object-storage.appdomain.cloud

The gateway path format is:
  /ibmcloud/gateway/{api-path}

The role can be provided via the X-Warden-Role header, or embedded in
the URL path:
  /ibmcloud/role/{role}/gateway/{api-path}

Standard API examples:
  /ibmcloud/role/{role}/gateway/v2/resource_instances
  /ibmcloud/role/{role}/gateway/v1/resource_groups
  /ibmcloud/role/{role}/gateway/v2/vpc/vpcs
  /ibmcloud/role/{role}/gateway/kubernetes/v1/clusters

COS Object Storage:
  Clients sign requests with SigV4 using their Warden JWT (as both
  aws_access_key_id and aws_secret_access_key) or role name (cert auth).
  Warden verifies the signature, re-signs with real IBM COS HMAC keys, and
  forwards to the regional COS endpoint.

  COS regions: us-south, us-east, eu-gb, eu-de, au-syd, jp-tok, etc.

Credential type: ibmcloud_keys (at least one mode required)
  - access_token: IAM bearer token for the REST API (API mode)
  - access_key_id: COS HMAC access key ID for Object Storage (COS mode)
  - secret_access_key: COS HMAC secret access key for Object Storage (COS mode)

Two credential source types are supported:
- ibm (iam_with_cos): IAM token minted from source API key + static COS HMAC keys
- hvault (dynamic_ibm): Dynamic API key from Vault IBM engine + IAM token exchange + static COS HMAC

Configuration:
- ibmcloud_url: IBM Cloud API base URL (default: https://cloud.ibm.com)
- max_body_size: Maximum request body size (default: 10MB, max: 100MB)
- timeout: Request timeout duration (default: 30s)
- auto_auth_path: Auth mount path for implicit authentication (e.g., 'auth/jwt/')
- default_role: Fallback role when not specified in the URL path
`
