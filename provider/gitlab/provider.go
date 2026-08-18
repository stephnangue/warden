package gitlab

import (
	"fmt"
	"net/http"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/sdk/githttp"
	"github.com/stephnangue/warden/provider/sdk/httpproxy"
)

// extractTokens resolves the two principals on a GitLab gateway request.
//
// Agent channels, in the provider's existing order: the native PRIVATE-TOKEN
// header, then Authorization: Bearer, then X-Warden-Token, then the HTTP Basic
// password (Git smart-HTTP carries the agent JWT that way, with the role in the
// Basic username). Note that Bearer precedes X-Warden-Token here — that order
// predates the user leg and must be preserved when userLeg is false.
//
// On a protected-resource mount an agent presented out of band —
// X-Warden-Agent-Token or a trusted client certificate — frees BOTH remaining
// slots for the user: the Bearer and the Basic password. See
// githttp.UserCredential.
//
// X-Warden-Token keeps its legacy position behind the Bearer, on both legs. It
// is the operator credential and never opens the user leg, so the ordering
// cannot cause a user token to be resolved as the agent. See
// logical.ExtractTokensDefault.
//
// Off the user leg the Basic password is ALWAYS the agent, even under a client
// certificate. An explicitly-presented credential beats an ambient one: a
// service-mesh sidecar puts a cert on nearly every request, and letting that
// suppress a JWT the client deliberately placed in the password slot would
// mis-attribute the workload to the sidecar — the same hazard that orders
// X-Warden-Agent-Token ahead of the cert in the shared rule. This is also
// exactly the pre-0.20 behaviour, so no request that worked before changes.
//
// The certificate only takes over as the agent on a protected-resource mount,
// where it is presented deliberately to free the password slot for the user.
//
// Extraction matrix. "-" means nothing extracted; an empty agent under a
// client certificate means the certificate authenticates the agent
// downstream. Off the user leg there is never a user.
// "eyJp" stands for a JWT-shaped secret, "x" for the placeholder git
// requires when the client has no token for the password slot.
//
//	request carries                            agent(off)  agent(on)  user(on)
//	Authorization: Bearer u                    u           u          -
//	X-Warden-Token: w + Bearer u               u           u          -
//	X-Warden-Agent-Token: a + Bearer u         u           a          u
//	client cert + Bearer u                     u           -          u
//	client cert only                           -           -          -
//	PRIVATE-TOKEN: n + Bearer u                n           n          u
//	PRIVATE-TOKEN: n + Bearer u + cert         n           n          u
//	Basic role:eyJp (JWT)                      eyJp        eyJp       -
//	Basic role:eyJp + client cert              eyJp        -          eyJp
//	Basic role:x (placeholder)                 x           x          -
//	Basic role:x + client cert                 x           -          -
//	X-Warden-Agent-Token: a + Basic role:eyJp  eyJp        a          eyJp
func extractTokens(r *http.Request, userLeg bool) (agent, user string) {
	if token := r.Header.Get("PRIVATE-TOKEN"); token != "" {
		return token, logical.UserBearer(r, userLeg)
	}
	if a, ok := logical.AgentOutOfBand(r, userLeg); ok {
		return a, githttp.UserCredential(r)
	}
	if token := logical.StripBearer(r.Header.Get("Authorization")); token != "" {
		return token, ""
	}
	if token := r.Header.Get("X-Warden-Token"); token != "" {
		return token, ""
	}
	if _, pwd, ok := r.BasicAuth(); ok && pwd != "" {
		return pwd, ""
	}
	return "", ""
}

// gitHooks bundles the three ProviderSpec hooks the mount wires for git
// smart-HTTP. GitLab serves REST under /api/v4/* and git under
// /<group>/<repo>.git, both off the same host root, so the configured
// gitlab_address works for both — git URL derivation is identity, which
// BuildHooks supplies automatically when DeriveGitURL is nil.
//
// "oauth2" is GitLab's published Basic Auth username convention: required
// for OAuth2-minted tokens and accepted for personal/project/group access
// tokens. Parallels GitHub's "x-access-token".
var gitHooks = githttp.BuildHooks(githttp.Options{
	BasicAuthUsername: "oauth2",
	CredentialType:    credential.TypeGitLabAccessToken,
	TokenField:        "access_token",
})

// Spec defines the GitLab provider configuration for the httpproxy framework.
var Spec = &httpproxy.ProviderSpec{
	Name:                 "gitlab",
	DefaultURL:           "", // GitLab requires explicit address
	URLConfigKey:         "gitlab_address",
	DefaultTimeout:       framework.DefaultTimeout,
	ParseStreamBody:      true,
	UserAgent:            "warden-gitlab-proxy",
	HelpText:             gitlabBackendHelp,
	ExtractCredentials:   httpproxy.TypedTokenExtractor(credential.TypeGitLabAccessToken, "access_token", "Authorization", "Bearer "),
	ExtractToken:         extractTokens,
	ExtraHeadersToRemove: []string{"PRIVATE-TOKEN"},
	ExtraConfigFields: map[string]*framework.FieldSchema{
		"git_max_body_size": githttp.MaxBodySizeField(),
	},
	OnConfigRead: func(state map[string]any) map[string]any {
		return map[string]any{
			"git_max_body_size": githttp.ReadMaxBodySize(state),
		}
	},
	OnConfigWrite: func(d *framework.FieldData, state map[string]any) (map[string]any, error) {
		if err := githttp.WriteMaxBodySize(d, state); err != nil {
			return nil, err
		}
		return state, nil
	},
	OnInitialize: func(config map[string]any, state map[string]any) map[string]any {
		githttp.InitializeMaxBodySize(config, state)
		return state
	},
	ValidateExtraConfig: func(conf map[string]any) error {
		addr, ok := conf["gitlab_address"].(string)
		if !ok || addr == "" {
			return fmt.Errorf("gitlab_address is required")
		}
		return nil
	},
	ResolveUpstream:          gitHooks.ResolveUpstream,
	GetAuthRoleFromRequest:   gitHooks.GetAuthRoleFromRequest,
	IsUnauthenticatedRequest: gitHooks.IsUnauthenticatedRequest,
}

// Factory creates a new GitLab provider backend.
var Factory = httpproxy.NewFactory(Spec)

const gitlabBackendHelp = `
The GitLab provider proxies both the GitLab REST API and Git smart-HTTP
(clone/fetch/push) with automatic credential management. The mount
dispatches per-request based on path shape:

  REST paths (/api/v4/...) → gitlab_address with Authorization: Bearer
    <access-token> on the outgoing call. Incoming requests may carry
    the Warden JWT via Authorization: Bearer, PRIVATE-TOKEN, or
    X-Warden-Token.

  Git smart-HTTP paths (<group>/<repo>.git/info/refs,
    .git/git-upload-pack, .git/git-receive-pack) → gitlab_address with
    HTTP Basic Auth carrying oauth2:<access-token> as the credential.

Warden performs implicit authentication on every request and obtains a
GitLab access token from the credential manager — either a personal
access token (PAT) or an OAuth2 token depending on the source
configuration. Clients never hold a long-lived token.

The REST gateway path format is:
  /gitlab/gateway/{api-path}

Examples:
  /gitlab/gateway/api/v4/projects
  /gitlab/gateway/api/v4/projects/123/repository/branches
  /gitlab/gateway/api/v4/groups/my-group/projects
  /gitlab/gateway/api/v4/projects/123/merge_requests

The Git clone URL carries the Warden role in the Basic Auth username
and the Warden JWT in the password:

  git clone https://<role>:$JWT@<warden-addr>/v1/gitlab/gateway/<group>/<repo>.git

Git's credential helpers cache on URL + username, so each role gets a
distinct credential entry.

The password slot always carries the agent credential, including for
clients that also present a TLS certificate: an explicitly-presented
credential takes precedence over an ambient one, so a service-mesh
sidecar certificate never displaces a JWT the client put there
deliberately.

On a mount configured with user_auth_path the roles shift — the
certificate becomes the agent and the password slot carries the
per-request USER identity, while the username keeps naming the
agent's role:

  git clone https://<agent-role>:$USER_JWT@<warden-addr>/v1/...

A cert-authenticated client with no user identity still has to put
something in the password slot, since Git requires one for Basic
auth. Any non-JWT value is treated as that placeholder and ignored,
so the request proceeds with the agent alone:

  git clone https://<agent-role>:x@<warden-addr>/v1/...

Self-hosted GitLab instances are supported by setting gitlab_address to
the instance URL (e.g., "https://gitlab.example.com"). REST and Git
paths share the same base — no separate Git host field is needed.

The role can be provided via the X-Warden-Role header, embedded in the
URL path (/gitlab/role/{role}/gateway/{api-path}), carried in the Basic
Auth username (Git smart-HTTP requests only), or defaulted by
default_role. Precedence: X-Warden-Role > path role > Basic Auth
username > default_role.

Header-routed alternative: clients that want a URL without the
/v1/gitlab/gateway/ prefix can send X-Warden-Provider: gitlab (and
optionally X-Warden-Namespace) via http.extraheader at clone time:

  git -c http.extraheader="X-Warden-Provider: gitlab" \
      clone https://<role>:$JWT@<warden-addr>/<group>/<repo>.git

http.extraheader persists into .git/config, so subsequent fetch/pull/push
carry the header automatically.

Configuration:
- gitlab_address: Base URL of the GitLab instance (required, e.g.,
    "https://gitlab.com")
- git_max_body_size: Cap on Git request bodies in bytes
    (default: 2 GiB, range: 1 MiB to 10 GiB)
- max_body_size: Cap on REST request bodies (default: 10MB, max: 100MB).
    Do not raise to accommodate Git pushes — git_max_body_size is the
    knob for that.
- timeout: Request timeout duration (e.g., '30s', '5m'). Tune up for
    large Git pushes.
- auto_auth_path: Auth mount path for implicit authentication (e.g.,
    'auth/jwt/')
- default_role: Fallback role when not specified by header or URL path
`
