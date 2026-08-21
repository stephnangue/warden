package datadog

import (
	"time"

	"github.com/stephnangue/warden/provider/sdk/httpproxy"
)

// DefaultDatadogURL is the default Datadog API base URL (US1 site)
const DefaultDatadogURL = "https://api.datadoghq.com"

// DefaultDatadogTimeout is the default request timeout for Datadog API calls
const DefaultDatadogTimeout = 30 * time.Second

// Spec defines the Datadog provider configuration for the httpproxy framework.
var Spec = &httpproxy.ProviderSpec{
	Name:            "datadog",
	DefaultURL:      DefaultDatadogURL,
	URLConfigKey:    "datadog_url",
	DefaultTimeout:  DefaultDatadogTimeout,
	ParseStreamBody: true,
	UserAgent:       "warden-datadog-proxy",
	HelpText:        datadogBackendHelp,
	ExtractCredentials: httpproxy.MultiFieldAPIKeyExtractor(
		map[string]string{"api_key": "DD-API-KEY"},
		map[string]string{"application_key": "DD-APPLICATION-KEY"},
	),

	// DD-APPLICATION-KEY is injected only when the credential carries one, so on
	// a spec without an application key a caller's own value would otherwise
	// reach the upstream beside Warden's DD-API-KEY — pairing an inbound
	// credential with the mount's identity. DD-API-KEY needs no strip: it is
	// injected on every request, and injection overwrites.
	ExtraHeadersToRemove: []string{"DD-APPLICATION-KEY"},
}

// Factory creates a new Datadog provider backend.
var Factory = httpproxy.NewFactory(Spec)

const datadogBackendHelp = `
The Datadog provider enables proxying requests to the Datadog REST API with
automatic credential management and API key injection.

Warden performs implicit authentication on every request and obtains a
Datadog API key (and optionally an Application key) from the credential
manager, injecting them into the proxied request's DD-API-KEY and
DD-APPLICATION-KEY headers. This allows Warden to broker Datadog access
without exposing keys to clients.

The gateway path format is:
  /datadog/gateway/{api-path}

Examples:
  /datadog/gateway/api/v1/query
  /datadog/gateway/api/v2/metrics
  /datadog/gateway/api/v1/monitor
  /datadog/gateway/api/v2/logs/events/search
  /datadog/gateway/api/v1/dashboard

The role can be provided via the X-Warden-Role header, or embedded in
the URL path:
  /datadog/role/{role}/gateway/{api-path}

Request body parsing is enabled, allowing policies to evaluate Datadog
request fields for fine-grained access control.

Credential source types:
- apikey: Static API key in spec config, optionally with an application_key
- hvault: Vault/OpenBao KV v2 secret holding the API key; use
  mint_method=static_apikey on the spec

A large part of the Datadog API needs an application key alongside the API
key. Both travel in one credential, and the source declares the second one:

  warden cred source create datadog -type=apikey \
    -config=api_url=https://api.datadoghq.com \
    -config=credential_fields=application_key

  warden cred spec create datadog-prod -source=datadog \
    -config=api_key=<DD_API_KEY> \
    -config=application_key=<DD_APP_KEY>

api_key is the only field a credential carries on its own; anything beside it
travels because credential_fields names it, and a spec setting application_key
against a source that does not declare it is rejected at write.

Only the apikey source resolves credential_fields, so the spec that Warden
mints must sit on one. Keeping the keys in a vault does not change that — it
changes where the values come from. Point the spec at a referenced secret with
credential chaining, and the apikey source resolves its declared fields from
the fetched payload:

  # holds both keys; lives on the hvault source
  warden cred spec create datadog-keys -type=key_value -source=corp-vault \
    -config=mint_method=kv2_read -config=kv2_mount=secret \
    -config=secret_path=apikeys/datadog

  # minted on the apikey source, which is what declares application_key
  warden cred spec create datadog-keyless -source=datadog \
    -config=secret_spec=datadog-keys

No secret_field is needed when the secret stores the keys under their own
names: api_key is found by name, and application_key is carried because the
apikey source declares it.

What will not work is mint_method=static_apikey against the hvault source
directly. There the hvault source mints the credential itself, the apikey
driver is never in the path, and nothing can declare a second field — the
credential arrives holding api_key alone.

Warden strips any DD-APPLICATION-KEY the caller sent before proxying, and
injects its own only when the credential carries one. A caller therefore
cannot supply an application key of their own to be used alongside the
mount's API key.

Configuration:
- datadog_url: Datadog API base URL (default: https://api.datadoghq.com)
- max_body_size: Maximum request body size (default: 10MB, max: 100MB)
- timeout: Request timeout duration (default: 30s)
- auto_auth_path: Auth mount path for implicit authentication (e.g., 'auth/jwt/')
- default_role: Fallback role when not specified in the URL path

The datadog_url must match your Datadog site:
  US1:     https://api.datadoghq.com (default)
  US3:     https://api.us3.datadoghq.com
  US5:     https://api.us5.datadoghq.com
  EU1:     https://api.datadoghq.eu
  AP1:     https://api.ap1.datadoghq.com
  AP2:     https://api.ap2.datadoghq.com
  US1-FED: https://api.ddog-gov.com
`
