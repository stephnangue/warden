package anthropic

import (
	"fmt"
	"net/http"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/sdk/httpproxy"
)

// DefaultAnthropicURL is the default Anthropic API base URL
const DefaultAnthropicURL = "https://api.anthropic.com"

// DefaultAnthropicTimeout is the default request timeout for AI inference
const DefaultAnthropicTimeout = 120 * time.Second

// extractTokens resolves the two principals on an Anthropic gateway request.
//
// Agent channels, in the provider's existing order: X-Warden-Token, then the
// native x-api-key header. On a protected-resource mount an agent presented out
// of band — X-Warden-Agent-Token or a trusted client certificate — frees
// Authorization to carry the user.
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
//	x-api-key: n + Bearer u             n           n          u
//	x-api-key: n + Bearer u + cert      n           n          u
func extractTokens(r *http.Request, userLeg bool) (agent, user string) {
	return logical.ExtractTokensWithChannels(r, userLeg, "X-Warden-Token", "x-api-key")
}

// anthropicCredentialExtractor injects the credential and the workspace it acts in.
//
// The auth header is chosen by credential type rather than fixed, because the two
// credential shapes Anthropic accepts disagree about where the workspace lives:
//
//   - A static key carries no workspace of its own. One issued for a single workspace
//     implies it; one an operator may use across several does not, and every request
//     made with the latter is refused unless it names a workspace. So the key travels
//     in x-api-key and the workspace beside it in a header.
//   - A federated token is issued for one workspace and carries that binding already.
//     The header is not read for such a token, so sending it would assert a workspace
//     twice and let the two disagree. The bearer branch deliberately emits none.
//
// workspace_id reaches the credential as an operator-declared adjunct, so a spec per
// tenant can point at a different workspace on one mount. It is also, upstream, the
// prompt-cache partition: two specs naming different workspaces can never share a
// cached prefix, which makes the granularity a cost decision and not only a billing
// one.
//
// An absent workspace_id emits no header rather than an empty one — an empty value
// is refused upstream, and would turn an optional field into a broken request.
func anthropicCredentialExtractor(req *logical.Request) (map[string]string, error) {
	if req.Credential == nil {
		return nil, fmt.Errorf("no credential available")
	}

	switch req.Credential.Type {
	case credential.TypeAPIKey:
		apiKey := req.Credential.Data["api_key"]
		if apiKey == "" {
			return nil, fmt.Errorf("credential missing api_key field")
		}
		headers := map[string]string{"x-api-key": apiKey}
		if workspaceID := req.Credential.Data["workspace_id"]; workspaceID != "" {
			headers["anthropic-workspace-id"] = workspaceID
		}
		return headers, nil

	case credential.TypeOAuthBearerToken:
		// api_key is this type's primary field too. A source that returns the
		// token as access_token is normalised onto api_key when the credential
		// is parsed, so there is only ever the one name to read here.
		token := req.Credential.Data["api_key"]
		if token == "" {
			return nil, fmt.Errorf("credential missing bearer token (api_key, or access_token as the source returned it)")
		}
		return map[string]string{"Authorization": "Bearer " + token}, nil

	default:
		return nil, fmt.Errorf("unsupported credential type: %s", req.Credential.Type)
	}
}

// Spec defines the Anthropic provider configuration for the httpproxy framework.
var Spec = &httpproxy.ProviderSpec{
	Name:               "anthropic",
	DefaultURL:         DefaultAnthropicURL,
	URLConfigKey:       "anthropic_url",
	DefaultTimeout:     DefaultAnthropicTimeout,
	ParseStreamBody:    true,
	UserAgent:          "warden-anthropic-proxy",
	HelpText:           anthropicBackendHelp,
	ExtractCredentials: anthropicCredentialExtractor,
	ExtractToken:       extractTokens,
	// Every header the extractor may set conditionally has to be stripped here.
	// Injection only overwrites on the branch that sets it, so a name missing from
	// this list would let a client's own value ride through beside the credential —
	// and for the workspace that means spending against, and reading the cache of,
	// a workspace the client chose under our credential. x-api-key is listed for a
	// second reason: the bearer branch injects nothing over it, and inbound it is
	// this provider's agent-token channel, so without the strip an agent's own token
	// would reach the upstream.
	ExtraHeadersToRemove: []string{"x-api-key", "anthropic-version", "anthropic-workspace-id"},
	DefaultHeaders:       map[string]string{"anthropic-version": "2023-06-01"},
}

// Factory creates a new Anthropic provider backend.
var Factory = httpproxy.NewFactory(Spec)

const anthropicBackendHelp = `
The Anthropic provider enables proxying requests to the Anthropic API with
automatic credential management and API key injection.

Warden performs implicit authentication on every request and obtains an
Anthropic credential from the credential manager, injecting it into the proxied
request. This allows Warden to broker Anthropic access without exposing
credentials to clients.

An api_key credential is injected as x-api-key. A bearer credential is injected
as Authorization: Bearer instead, and carries no workspace header, because such
a token is issued for one workspace and already binds it.

A credential may carry a workspace_id beside the key, which is injected as
anthropic-workspace-id. A key an operator may use across several workspaces is
refused upstream unless a request names one, so such a key needs this field. The
workspace is also the upstream prompt-cache partition: specs naming different
workspaces never share a cached prefix, so prefer one spec per tenant or team
over one per agent.

To carry it, name the field on an apikey source and set it on the spec:

  warden cred source create anthropic-keys -json '{
    "type": "apikey",
    "config": {
      "credential_fields": "workspace_id"
    }
  }'

Only an apikey source carries adjunct fields. A spec setting workspace_id on any
other source type is rejected when it is written, rather than minting a
credential silently missing it.

The gateway path format is:
  /anthropic/gateway/{api-path}

Examples:
  /anthropic/gateway/v1/messages
  /anthropic/gateway/v1/models

The role can be provided via the X-Warden-Role header, or embedded in
the URL path:
  /anthropic/role/{role}/gateway/{api-path}

Request body parsing is enabled, allowing policies to evaluate AI request
fields such as model, max_tokens, temperature, and stream. This enables
fine-grained cost control and usage policies.

Configuration:
- anthropic_url: Anthropic API base URL (default: https://api.anthropic.com)
- max_body_size: Maximum request body size (default: 10MB, max: 100MB)
- timeout: Request timeout duration (default: 120s for AI inference)
- auto_auth_path: Auth mount path for implicit authentication (e.g., 'auth/jwt/')
- default_role: Fallback role when not specified in the URL path
`
