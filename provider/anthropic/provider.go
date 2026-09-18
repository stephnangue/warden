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
	Name:            "anthropic",
	DefaultURL:      DefaultAnthropicURL,
	URLConfigKey:    "anthropic_url",
	DefaultTimeout:  DefaultAnthropicTimeout,
	ParseStreamBody: true,
	UserAgent:       "warden-anthropic-proxy",
	HelpText:        anthropicBackendHelp,
	ExtractToken:    extractTokens,

	// The pass-through policy, for a mount whose config has never been written
	// and so has no extractor in state. Every other mount gets its own from
	// ResolveUpstream.
	ExtractCredentials: newExtractor(passThroughBetas, ""),

	// Every header the extractor may set conditionally has to be stripped here.
	// Injection only overwrites on the branch that sets it, so a name missing from
	// this list would let a client's own value ride through beside the credential —
	// and for the workspace that means spending against, and reading the cache of,
	// a workspace the client chose under our credential. x-api-key is listed for a
	// second reason: the bearer branch injects nothing over it, and inbound it is
	// this provider's agent-token channel, so without the strip an agent's own token
	// would reach the upstream.
	//
	// anthropic-beta is stripped so the policy decides what reaches the upstream;
	// the extractor puts back whatever it allows. anthropic-version is stripped so
	// a client cannot pin its own, and DynamicHeaders supplies the mount's.
	// anthropic-user-profile-id is stripped so the only profile a request is
	// attributed to is one read from the user's verified identity — a client
	// naming its own would be claiming another party's standing.
	ExtraHeadersToRemove: []string{
		"x-api-key", "anthropic-version", "anthropic-workspace-id", "anthropic-beta",
		"anthropic-user-profile-id",
	},

	DynamicHeaders:      dynamicHeaders,
	ExtraConfigFields:   extraConfigFields,
	ResolveUpstream:     resolveUpstream,
	OnConfigWrite:       onConfigWrite,
	OnConfigRead:        onConfigRead,
	OnInitialize:        onInitialize,
	ValidateExtraConfig: validateExtraConfig,
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

The mount sends its own anthropic-version, and decides which anthropic-beta
values reach the upstream. A client's own anthropic-version is replaced. Its
anthropic-beta values all pass through unless beta_allowlist is set, in which
case only the listed ones do; beta_required values are added to every request
whatever the client sent. With neither set, the client's header is forwarded
exactly as sent; otherwise the names are rejoined, each sent once:

  warden write anthropic/config <<EOF
  {
    "anthropic_version": "2023-06-01",
    "beta_allowlist": "context-management-2025-06-27",
    "beta_required": "user-profiles-2026-09-04"
  }
  EOF

beta_allowlist is "*" by default, which passes every client beta. An empty
value passes none, leaving only beta_required. Warden cannot check that the
organization has access to a beta, and the upstream refuses a request carrying
one it does not, so a beta_required value the organization lacks fails every
request through the mount.

A request can be attributed to the end user it is made for, sent as
anthropic-user-profile-id. The id is an upstream profile (uprof_...), created
with the upstream's user profile API; Warden forwards one, it never creates one.
It is read from the requesting user's verified token metadata, so map the claim
holding it on the user auth role, then name that metadata key on the mount
together with the beta the upstream requires for it:

  warden write auth/jwt/role/end-users <<EOF
  {
    "metadata_claims": {
      "anthropic_profile": "anthropic_user_profile_id"
    }
  }
  EOF

  warden write anthropic/config <<EOF
  {
    "beta_required": "user-profiles-2026-09-04",
    "user_profile_metadata_key": "anthropic_user_profile_id"
  }
  EOF

Only the user's own metadata is read, never the agent's, so a request with no
user attributes no one. A value that is not a profile id is not sent. A client's
own anthropic-user-profile-id is always removed.

Configuration:
- anthropic_url: Anthropic API base URL (default: https://api.anthropic.com)
- max_body_size: Maximum request body size (default: 10MB, max: 100MB)
- timeout: Request timeout duration (default: 120s for AI inference)
- auto_auth_path: Auth mount path for implicit authentication (e.g., 'auth/jwt/')
- default_role: Fallback role when not specified in the URL path
- anthropic_version: API version sent as anthropic-version (default: 2023-06-01)
- beta_allowlist: Comma-separated client betas allowed through (default: "*", all)
- beta_required: Comma-separated betas added to every request (default: none)
- user_profile_metadata_key: User metadata key holding the profile id (default: none)
`
