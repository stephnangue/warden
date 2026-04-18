package ibmcloud

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/dualgateway"
)

// DefaultIBMCloudURL is a placeholder — ignored in API mode when RewriteAPITarget routes
// by path. Kept only because the dualgateway framework requires DefaultURL + URLConfigKey.
const DefaultIBMCloudURL = "https://cloud.ibm.com"

// DefaultIBMCloudTimeout is the default request timeout for IBM Cloud API calls.
const DefaultIBMCloudTimeout = 30 * time.Second

// defaultIBMAllowedHostSuffixes is the default closed allowlist of hostname suffixes
// the gateway will forward API requests to. Includes COS endpoints (appdomain.cloud)
// so operators who narrow the list can still use the SigV4 path if they wish.
var defaultIBMAllowedHostSuffixes = []string{".cloud.ibm.com", ".appdomain.cloud"}

// hostnameRegex is a pragmatic RFC 1123-ish hostname validator. Labels must be
// 1-63 chars of [a-z0-9-], not starting/ending with '-', joined by dots, with at
// least one dot. No ports, no userinfo, no paths.
var hostnameRegex = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

// Spec defines the IBM Cloud dual-mode gateway provider.
//
// API mode routes to multiple IBM Cloud service hostnames via the first path segment:
//
//	/v1/ibmcloud/role/{role}/gateway/{host}/{service-path}
//
// COS mode detects SigV4 automatically and forwards to s3.<region>.cloud-object-storage.appdomain.cloud
// (or the configured cos_endpoint_type variant).
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

	ExtraConfigKeys: []string{"cos_endpoint_type", "allowed_host_suffixes"},
	ExtraConfigFields: map[string]*framework.FieldSchema{
		"cos_endpoint_type": {
			Type:        framework.TypeString,
			Description: "IBM COS endpoint type: 'public' (default), 'private' (VPC-only), or 'direct' (Classic Infrastructure)",
		},
		"allowed_host_suffixes": {
			Type: framework.TypeCommaStringSlice,
			Description: "Hostname suffixes permitted as API gateway targets. " +
				"Default: '.cloud.ibm.com,.appdomain.cloud'. Each entry must begin with a dot. " +
				"Use a single '*' to disable suffix checking (not recommended).",
		},
	},
	OnConfigParsed: func(config map[string]any) map[string]any {
		suffixes := parseHostSuffixes(config["allowed_host_suffixes"])
		if len(suffixes) == 0 {
			suffixes = defaultIBMAllowedHostSuffixes
		}
		return map[string]any{
			"cos_endpoint_type":     framework.GetConfigString(config, "cos_endpoint_type", ""),
			"allowed_host_suffixes": suffixes,
		}
	},

	S3Endpoint: func(state map[string]any, region string) string {
		endpointType, _ := state["cos_endpoint_type"].(string)
		switch endpointType {
		case "private":
			return fmt.Sprintf("s3.private.%s.cloud-object-storage.appdomain.cloud", region)
		case "direct":
			return fmt.Sprintf("s3.direct.%s.cloud-object-storage.appdomain.cloud", region)
		default:
			return fmt.Sprintf("s3.%s.cloud-object-storage.appdomain.cloud", region)
		}
	},

	RewriteAPITarget: func(providerURL, apiPath string, state map[string]any) (string, error) {
		host, rest, err := splitHostFromPath(apiPath)
		if err != nil {
			return "", err
		}
		suffixes, _ := state["allowed_host_suffixes"].([]string)
		if len(suffixes) == 0 {
			suffixes = defaultIBMAllowedHostSuffixes
		}
		if !hostAllowed(host, suffixes) {
			return "", fmt.Errorf("host %q not in allowed_host_suffixes", host)
		}
		return "https://" + host + rest, nil
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

// splitHostFromPath parses "/host/rest/of/path" into host and rest.
// Returns error for empty, malformed, IP-literal, or otherwise unsafe hosts.
func splitHostFromPath(apiPath string) (host string, rest string, err error) {
	trimmed := strings.TrimPrefix(apiPath, "/")
	if trimmed == "" {
		return "", "", fmt.Errorf("missing target host in path — expected /gateway/{host}/...")
	}

	slash := strings.Index(trimmed, "/")
	if slash < 0 {
		host = trimmed
		rest = "/"
	} else {
		host = trimmed[:slash]
		rest = trimmed[slash:]
	}

	if err := validateHost(host); err != nil {
		return "", "", err
	}
	return host, rest, nil
}

// validateHost rejects anything that isn't a plain, lowercase, hostname.
func validateHost(host string) error {
	if host == "" {
		return fmt.Errorf("missing target host in path")
	}
	if len(host) > 253 {
		return fmt.Errorf("target host too long (>253 chars)")
	}
	// Fast rejection of obvious attacks.
	if strings.ContainsAny(host, ":@/?#[] \t") {
		return fmt.Errorf("invalid target host %q (contains port, userinfo, or path characters)", host)
	}
	// Reject uppercase so suffix comparison is case-sensitive on the canonical form.
	if strings.ToLower(host) != host {
		return fmt.Errorf("target host %q must be lowercase", host)
	}
	if ip := net.ParseIP(host); ip != nil {
		return fmt.Errorf("target host %q must be a hostname, not an IP literal", host)
	}
	if !hostnameRegex.MatchString(host) {
		return fmt.Errorf("target host %q is not a valid hostname", host)
	}
	return nil
}

// hostAllowed checks that host ends with one of the configured suffixes.
// A single entry of "*" disables the check.
func hostAllowed(host string, suffixes []string) bool {
	if len(suffixes) == 1 && suffixes[0] == "*" {
		return true
	}
	for _, s := range suffixes {
		if s == "" {
			continue
		}
		if strings.HasSuffix(host, s) {
			return true
		}
	}
	return false
}

// parseHostSuffixes normalizes allowed_host_suffixes from config. Accepts nil,
// []string, []any, or comma-separated string. Entries are trimmed and lowercased.
// Entries not starting with '.' are silently dropped, except the single wildcard "*".
func parseHostSuffixes(raw any) []string {
	if raw == nil {
		return nil
	}
	var items []string
	switch v := raw.(type) {
	case []string:
		items = v
	case []any:
		for _, x := range v {
			if s, ok := x.(string); ok {
				items = append(items, s)
			}
		}
	case string:
		if v == "" {
			return nil
		}
		items = strings.Split(v, ",")
	default:
		return nil
	}

	var out []string
	for _, it := range items {
		it = strings.ToLower(strings.TrimSpace(it))
		if it == "" {
			continue
		}
		if it == "*" {
			// Wildcard must stand alone to have effect — callers short-circuit.
			return []string{"*"}
		}
		if !strings.HasPrefix(it, ".") {
			// Drop invalid entries (no leading dot); prevents "cloud.ibm.com" from matching
			// "evilcloud.ibm.com". README documents this rule.
			continue
		}
		out = append(out, it)
	}
	return out
}

const ibmcloudBackendHelp = `
The IBM Cloud provider enables proxying requests to IBM Cloud APIs with
automatic credential management and dual authentication mode support.

The provider auto-detects the request type based on the Authorization header:
- Standard API requests: injects Authorization: Bearer with the IAM token and
  forwards to the IBM Cloud service whose hostname is embedded in the request path.
- COS Object Storage requests (AWS SigV4): verifies the incoming signature, re-signs
  with real IBM COS HMAC credentials, and forwards to s3.{region}.cloud-object-storage.appdomain.cloud.

API path format:
  /v1/ibmcloud/role/{role}/gateway/{ibm-host}/{service-path}

Examples:
  /v1/ibmcloud/role/user/gateway/resource-controller.cloud.ibm.com/v2/resource_instances
  /v1/ibmcloud/role/user/gateway/us-south.iaas.cloud.ibm.com/v1/vpcs?version=2024-06-01
  /v1/ibmcloud/role/user/gateway/containers.cloud.ibm.com/global/v2/vpc/getClusters
  /v1/ibmcloud/role/user/gateway/api.eu-de.codeengine.cloud.ibm.com/v2/projects

Target hosts are restricted via allowed_host_suffixes (default: .cloud.ibm.com
and .appdomain.cloud) to prevent the provider from being used as an open proxy.

COS Object Storage:
  Clients sign requests with SigV4 using their Warden JWT (as both
  aws_access_key_id and aws_secret_access_key) or role name (cert auth).
  Warden verifies the signature, re-signs with real IBM COS HMAC keys, and
  forwards to the regional COS endpoint.

  COS regions: us-south, us-east, eu-gb, eu-de, au-syd, jp-tok, br-sao, ca-tor, etc.

Credential type: ibmcloud_keys (at least one mode required)
  - access_token: IAM bearer token for the REST API (API mode)
  - access_key_id: COS HMAC access key ID for Object Storage (COS mode)
  - secret_access_key: COS HMAC secret access key for Object Storage (COS mode)

Two credential source types are supported:
- ibm (iam_with_cos): IAM token minted from source API key + static COS HMAC keys
- hvault (dynamic_ibm): Dynamic API key from Vault IBM engine + IAM token exchange + static COS HMAC

Configuration:
- ibmcloud_url: Retained for compatibility; ignored in API mode (path encodes the host)
- cos_endpoint_type: 'public' (default), 'private', or 'direct'
- allowed_host_suffixes: Comma-separated hostname suffixes permitted as API targets
- max_body_size: Maximum request body size (default: 10MB, max: 100MB)
- timeout: Request timeout duration (default: 30s)
- auto_auth_path: Auth mount path for implicit authentication (e.g., 'auth/jwt/')
- default_role: Fallback role when not specified in the URL path
`
