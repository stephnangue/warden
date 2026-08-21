package atlassian

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/sdk/httpproxy"
)

// DefaultAtlassianURL is a placeholder — operators must set atlassian_url per mount
// to the product-specific base URL (see help text for examples).
const DefaultAtlassianURL = "https://your-domain.atlassian.net"

// DefaultAtlassianTimeout is the default request timeout for Atlassian API calls.
const DefaultAtlassianTimeout = 30 * time.Second

// atlassianExtractor injects credentials as Basic Auth or Bearer depending on
// what fields are present in the credential data:
//
//   - email + api_key → Authorization: Basic base64(email:api_key)
//     Used for: Atlassian Cloud personal API tokens, Bitbucket app passwords,
//     and Atlassian Data Center pre-PAT basic auth.
//
//   - api_key only → Authorization: Bearer api_key
//     Used for: Atlassian Data Center Personal Access Tokens (PATs),
//     OAuth 2.0 access tokens, and Atlassian Admin API org keys.
//
// api_key is the only field the credential type carries on its own, so email
// reaches the credential because the apikey source declares it in
// optional_metadata. Its value resolves from a chained secret's payload first,
// then from spec config.
func atlassianExtractor(req *logical.Request) (map[string]string, error) {
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
	if email := req.Credential.Data["email"]; email != "" {
		encoded := base64.StdEncoding.EncodeToString([]byte(email + ":" + apiKey))
		return map[string]string{"Authorization": "Basic " + encoded}, nil
	}
	return map[string]string{"Authorization": "Bearer " + apiKey}, nil
}

// Spec defines the Atlassian provider configuration for the httpproxy framework.
//
// A single provider type supports all Atlassian products (Jira, Confluence,
// Jira Service Management, Compass, Bitbucket, Admin API) by mounting multiple
// instances with different atlassian_url values.
var Spec = &httpproxy.ProviderSpec{
	Name:               "atlassian",
	DefaultURL:         DefaultAtlassianURL,
	URLConfigKey:       "atlassian_url",
	DefaultTimeout:     DefaultAtlassianTimeout,
	ParseStreamBody:    true,
	UserAgent:          "warden-atlassian-proxy",
	HelpText:           atlassianBackendHelp,
	ExtractCredentials: atlassianExtractor,
}

// Factory creates a new Atlassian provider backend.
var Factory = httpproxy.NewFactory(Spec)

const atlassianBackendHelp = `
The Atlassian provider enables proxying requests to Atlassian Cloud and Data
Center REST APIs with automatic credential management and auth header injection.

Warden performs implicit authentication on every request and obtains an
Atlassian credential from the credential manager, injecting it into the
proxied request. Auth mode is detected automatically from the credential data:

  Basic Auth (email + api_key):
    Used for Atlassian Cloud personal API tokens, Bitbucket app passwords,
    and Data Center basic auth — which is what Atlassian Cloud tokens
    require, so this is the usual mode rather than the exception.

    api_key is the only field a credential carries on its own, so the email
    must be declared on the source:

      warden cred source create atlassian -type=apikey \
        -config=api_url=https://<domain>.atlassian.net \
        -config=optional_metadata=email

      warden cred spec create jira-svc -source=atlassian \
        -config=api_key=<ATLASSIAN_TOKEN> \
        -config=email=svc@example.com

    Without the declaration the spec is rejected at write, rather than
    minting a credential with no email and quietly falling back to Bearer.

    To keep the token in a vault, reference it with credential chaining. The
    spec still sits on the apikey source — that is what declares email and
    resolves it — while the referenced spec holds the secret:

      warden cred spec create atlassian-token -type=key_value \
        -source=corp-vault -config=mint_method=kv2_read \
        -config=kv2_mount=secret -config=secret_path=apikeys/atlassian

      warden cred spec create jira-keyless -source=atlassian \
        -config=secret_spec=atlassian-token \
        -config=email=svc@example.com

    A declared field resolves from the fetched secret first and from spec
    config second, so the email can stay inline as above, or move into the
    secret alongside the token. What will not work is mint_method=static_apikey
    against the hvault source directly: there the hvault source mints the
    credential, the apikey driver is never in the path, and nothing can
    declare a second field.

  Bearer (api_key only):
    Used for Atlassian Data Center Personal Access Tokens (PATs, DC 8.14+/7.9+),
    OAuth 2.0 access tokens (3LO or client credentials), and Admin API org keys.

This single provider type supports the full Atlassian ecosystem by mounting
multiple instances with different atlassian_url values:

  Jira Cloud:               atlassian_url=https://<domain>.atlassian.net/rest/api/3
  Confluence Cloud:         atlassian_url=https://<domain>.atlassian.net/wiki/rest/api
  Jira Service Management:  atlassian_url=https://<domain>.atlassian.net/rest/servicedeskapi
  Compass:                  atlassian_url=https://<domain>.atlassian.net/gateway/api/compass/v1
  Atlassian Admin API:      atlassian_url=https://api.atlassian.com
  Bitbucket Cloud:          atlassian_url=https://api.bitbucket.org/2.0
  Jira Data Center:         atlassian_url=https://jira.company.internal/rest/api/2
  Confluence Data Center:   atlassian_url=https://confluence.company.internal/rest/api

The gateway path format is:
  /<mount>/gateway/{api-path}

The role can be provided via the X-Warden-Role header, or embedded in
the URL path:
  /<mount>/role/{role}/gateway/{api-path}

Example API paths (Jira Cloud):
  /my-jira/gateway/rest/api/3/myself
  /my-jira/gateway/rest/api/3/issue
  /my-jira/gateway/rest/api/3/project
  /my-jira/gateway/rest/api/3/search

Example API paths (Confluence Cloud v2):
  /my-confluence/gateway/wiki/api/v2/pages
  /my-confluence/gateway/wiki/api/v2/spaces
  /my-confluence/gateway/wiki/api/v2/blogposts

Example API paths (Jira Service Management):
  /my-jsm/gateway/rest/servicedeskapi/servicedesk
  /my-jsm/gateway/rest/servicedeskapi/request

Example API paths (Bitbucket Cloud):
  /my-bitbucket/gateway/2.0/repositories/{workspace}
  /my-bitbucket/gateway/2.0/user

Credential source type:
- apikey: Static Atlassian API token, PAT, app password, or OAuth access token.
  For Cloud personal tokens, declare optional_metadata=email on the source and
  set email on the spec to enable Basic Auth mode; the token itself may be
  inline or reached from a vault by credential chaining (see above).

Configuration:
- atlassian_url: Atlassian product API base URL (required — no universal default)
- max_body_size: Maximum request body size (default: 10MB, max: 100MB)
- timeout: Request timeout duration (default: 30s)
- auto_auth_path: Auth mount path for implicit authentication (e.g., 'auth/jwt/')
- default_role: Fallback role when not specified in the URL path
`
