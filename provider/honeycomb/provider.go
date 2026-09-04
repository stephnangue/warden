package honeycomb

import (
	"fmt"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/sdk/httpproxy"
)

// DefaultHoneycombURL is the default Honeycomb API base URL (US region).
// For EU region, configure honeycomb_url to https://api.eu1.honeycomb.io.
const DefaultHoneycombURL = "https://api.honeycomb.io"

// DefaultHoneycombTimeout is the default request timeout for Honeycomb API calls.
const DefaultHoneycombTimeout = 30 * time.Second

// honeycombExtractor injects credentials as the appropriate Honeycomb auth header.
// key_id selects the mode; api_key carries the secret in both:
//
//   - key_id present → Authorization: Bearer <key_id>:<api_key>
//     Used for: Management key operations (V2 key management API), where
//     Honeycomb's own UI calls api_key the "key secret".
//
//   - key_id absent → X-Honeycomb-Team: <api_key>
//     Used for: Ingest and Configuration key operations (V1/V2 data APIs).
//
// The secret half is api_key rather than a separate key_secret field because
// api_key is what the credential type carries as its secret, and the type
// guarantees it is non-empty. A distinct key_secret would have to travel
// alongside a meaningless api_key just to satisfy that guarantee, so management
// mode could never be configured without one.
func honeycombExtractor(req *logical.Request) (map[string]string, error) {
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

	// Management key mode: key_id names the key, api_key is its secret.
	if keyID := req.Credential.Data["key_id"]; keyID != "" {
		return map[string]string{
			"Authorization": "Bearer " + keyID + ":" + apiKey,
		}, nil
	}

	// Ingest/configuration key mode: api_key → X-Honeycomb-Team header
	return map[string]string{"X-Honeycomb-Team": apiKey}, nil
}

// Spec defines the Honeycomb provider configuration for the httpproxy framework.
//
// Honeycomb uses X-Honeycomb-Team for ingest/configuration keys and Bearer tokens
// for management keys. A single provider type supports both US and EU regions by
// mounting multiple instances with different honeycomb_url values.
var Spec = &httpproxy.ProviderSpec{
	Name:               "honeycomb",
	DefaultURL:         DefaultHoneycombURL,
	URLConfigKey:       "honeycomb_url",
	DefaultTimeout:     DefaultHoneycombTimeout,
	ParseStreamBody:    true,
	UserAgent:          "warden-honeycomb-proxy",
	HelpText:           honeycombBackendHelp,
	ExtractCredentials: honeycombExtractor,

	// X-Honeycomb-Team is injected only in ingest mode, so in management mode a
	// caller's own value would otherwise ride through untouched alongside the
	// Authorization header Warden sets — an inbound credential reaching the
	// upstream under the mount's identity. Headers injected on every branch need
	// no strip, since injection overwrites; conditionally injected ones do.
	ExtraHeadersToRemove: []string{"X-Honeycomb-Team"},
}

// Factory creates a new Honeycomb provider backend.
var Factory = httpproxy.NewFactory(Spec)

const honeycombBackendHelp = `
The Honeycomb provider enables proxying requests to the Honeycomb API with
automatic credential management and auth header injection.

Warden performs implicit authentication on every request and obtains a
Honeycomb credential from the credential manager, injecting it into the
proxied request. Auth mode is detected automatically from the credential data:

  Ingest/Configuration key (default, no key_id on the credential):
    Injected as X-Honeycomb-Team header.
    Used for: sending events, querying data, managing datasets, triggers,
    boards, SLOs, and other environment-scoped operations.

  Management key (key_id present on the credential):
    Injected as Authorization: Bearer <key_id>:<api_key> header.
    Used for: creating, listing, and deleting API keys via the V2
    key management API.

    Put Honeycomb's "Key ID" in key_id and its "Key Secret" in api_key --
    api_key is the credential's secret field whichever mode is in use.

    key_id is what selects the mode, so setting it on an ingest credential
    switches the mount to management mode. On an apikey source it must also
    be listed in the source's credential_fields, since that driver copies
    only api_key and the fields named there into the credential; a local
    source carries it without further configuration.

This provider supports both Honeycomb regions by mounting multiple
instances with different honeycomb_url values:

  US region (default): honeycomb_url=https://api.honeycomb.io
  EU region:           honeycomb_url=https://api.eu1.honeycomb.io

The gateway path format is:
  /honeycomb/gateway/{api-path}

The role can be provided via the X-Warden-Role header, or embedded in
the URL path:
  /honeycomb/role/{role}/gateway/{api-path}

Example API paths:
  /honeycomb/gateway/1/events/{dataset}
  /honeycomb/gateway/1/batch/{dataset}
  /honeycomb/gateway/1/queries/{dataset}
  /honeycomb/gateway/1/boards
  /honeycomb/gateway/1/triggers
  /honeycomb/gateway/1/markers/{dataset}
  /honeycomb/gateway/1/slos
  /honeycomb/gateway/1/auth

V2 key management paths (requires management key credentials):
  /honeycomb/gateway/2/teams/{team}/api-keys

Credential source types:
- apikey: An ingest, configuration or management key. Held inline on the spec,
  or — keyless — fetched per request from another cred spec via secret_spec,
  so the key lives in your vault and Warden stores none of it. Management mode
  additionally needs key_id in the source's credential_fields, since that
  driver carries only api_key and the fields named there.

Configuration:
- honeycomb_url: Honeycomb API base URL (default: https://api.honeycomb.io)
- max_body_size: Maximum request body size (default: 10MB, max: 100MB)
- timeout: Request timeout duration (default: 30s)
- auto_auth_path: Auth mount path for implicit authentication (e.g., 'auth/jwt/')
- default_role: Fallback role when not specified in the URL path
`
