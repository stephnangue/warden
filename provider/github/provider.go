package github

import (
	"net/http"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/sdk/githttp"
	"github.com/stephnangue/warden/provider/sdk/httpproxy"
)

// DefaultGitHubURL is the default GitHub API base URL
const DefaultGitHubURL = "https://api.github.com"

// DefaultAPIVersion is the default GitHub REST API version
const DefaultAPIVersion = "2022-11-28"

// extractTokens resolves the two principals on a GitHub gateway request.
//
// Agent channels, in the provider's existing order: X-Warden-Token, then
// Authorization: Bearer, then the HTTP Basic password (Git smart-HTTP carries
// the agent JWT that way, with the role in the Basic username).
//
// On a protected-resource mount an agent presented out of band —
// X-Warden-Agent-Token or a trusted client certificate — frees BOTH remaining
// slots for the user: the Bearer and the Basic password. See
// githttp.UserCredential.
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
//	X-Warden-Token: w + Bearer u               w           w          -
//	X-Warden-Agent-Token: a + Bearer u         u           a          u
//	client cert + Bearer u                     u           -          u
//	client cert only                           -           -          -
//	Basic role:eyJp (JWT)                      eyJp        eyJp       -
//	Basic role:eyJp + client cert              eyJp        -          eyJp
//	Basic role:x (placeholder)                 x           x          -
//	Basic role:x + client cert                 x           -          -
//	X-Warden-Agent-Token: a + Basic role:eyJp  eyJp        a          eyJp
func extractTokens(r *http.Request, userLeg bool) (agent, user string) {
	// X-Warden-Token is the operator credential and never opens the user leg.
	// See logical.ExtractTokensDefault.
	if token := r.Header.Get(logical.HeaderWardenToken); token != "" {
		return token, ""
	}
	if a, ok := logical.AgentOutOfBand(r, userLeg); ok {
		return a, githttp.UserCredential(r)
	}
	if token := logical.StripBearer(r.Header.Get("Authorization")); token != "" {
		return token, ""
	}
	if _, pwd, ok := r.BasicAuth(); ok && pwd != "" {
		return pwd, ""
	}
	return "", ""
}

// Spec defines the GitHub provider configuration for the httpproxy framework.
var Spec = &httpproxy.ProviderSpec{
	Name:               "github",
	DefaultURL:         DefaultGitHubURL,
	URLConfigKey:       "github_url",
	DefaultTimeout:     framework.DefaultTimeout,
	ParseStreamBody:    true,
	UserAgent:          "warden-github-proxy",
	HelpText:           githubBackendHelp,
	ExtractCredentials: httpproxy.TypedTokenExtractor(credential.TypeGitHubToken, "token", "Authorization", "token "),
	ExtractToken:       extractTokens,
	DefaultAccept:      "application/vnd.github+json",
	ExtraConfigFields: map[string]*framework.FieldSchema{
		"api_version": {
			Type:        framework.TypeString,
			Description: "GitHub REST API version for X-GitHub-Api-Version header (default: 2022-11-28)",
			Default:     DefaultAPIVersion,
		},
		"git_max_body_size": githttp.MaxBodySizeField(),
	},
	DynamicHeaders: func(state map[string]any) map[string]string {
		ver, _ := state["api_version"].(string)
		if ver == "" {
			ver = DefaultAPIVersion
		}
		return map[string]string{"X-GitHub-Api-Version": ver}
	},
	OnConfigRead: func(state map[string]any) map[string]any {
		ver, _ := state["api_version"].(string)
		if ver == "" {
			ver = DefaultAPIVersion
		}
		return map[string]any{
			"api_version":       ver,
			"git_max_body_size": githttp.ReadMaxBodySize(state),
		}
	},
	OnConfigWrite: func(d *framework.FieldData, state map[string]any) (map[string]any, error) {
		// Validate before mutating so a rejected write leaves no partial
		// state for the caller to observe.
		if err := githttp.WriteMaxBodySize(d, state); err != nil {
			return nil, err
		}
		if val, ok := d.GetOk("api_version"); ok {
			ver := val.(string)
			if ver != "" {
				state["api_version"] = ver
			}
		}
		return state, nil
	},
	OnInitialize: func(config map[string]any, state map[string]any) map[string]any {
		if ver, ok := config["api_version"].(string); ok && ver != "" {
			state["api_version"] = ver
		} else {
			state["api_version"] = DefaultAPIVersion
		}
		githttp.InitializeMaxBodySize(config, state)
		return state
	},
	ResolveUpstream:          gitHooks.ResolveUpstream,
	GetAuthRoleFromRequest:   gitHooks.GetAuthRoleFromRequest,
	IsUnauthenticatedRequest: gitHooks.IsUnauthenticatedRequest,
}

// Factory creates a new GitHub provider backend.
var Factory = httpproxy.NewFactory(Spec)

const githubBackendHelp = `
The GitHub provider proxies both the GitHub REST API and Git smart-HTTP
(clone/fetch/push) with automatic credential management. The mount
dispatches per-request based on path shape:

  REST paths (/repos, /user, /orgs, ...) → api.github.com with
    Authorization: token <PAT>.

  Git smart-HTTP paths (<owner>/<repo>.git/info/refs,
    .git/git-upload-pack, .git/git-receive-pack) → github.com (or the
    GHE host derived from github_url) with HTTP Basic Auth carrying
    x-access-token:<PAT> as the credential.

Warden performs implicit authentication on every request and obtains a
GitHub token from the credential manager. Clients never hold a PAT.

The REST gateway path format is:
  /github/gateway/{api-path}

Examples:
  /github/gateway/repos/owner/repo
  /github/gateway/user
  /github/gateway/orgs/myorg/repos
  /github/gateway/repos/owner/repo/pulls?state=open

The Git clone URL carries the Warden role in the Basic Auth username
and the Warden JWT in the password:

  git clone https://<role>:$JWT@<warden-addr>/v1/github/gateway/<owner>/<repo>.git

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
agent's role.

Git sends no credentials until it is challenged, so the password slot
is filled only after a 401. Where the agent is a certificate, the
opening request passes through and the upstream issues that challenge;
where it arrives on X-Warden-Agent-Token, Warden issues it, since that
request carries no Basic username to resolve a role from. Either way
Git retries with the role in the username and the user identity in the
password. Setting X-Warden-Role or the mount's default_role lets the
first request succeed outright and skips the round trip.

Keep credentials out of the clone URL. Git writes the remote verbatim
into .git/config, so anything embedded there persists in plaintext in
every clone and shows up in "git remote -v" output. Let Git prompt
instead, and pin an empty credential helper into the clone so a
short-lived token is not cached and replayed once it expires — a stale
replay surfaces only as "Authentication failed", indistinguishable
from a wrong credential:

  git clone --config credential.helper= \
      https://<agent-role>@<warden-addr>/v1/...

The role may also travel in the path rather than the username. Git's
helpers ignore the path unless credential.useHttpPath is set, so every
role then shares one cache entry:

  git clone https://<warden-addr>/v1/github/role/<agent-role>/gateway/...

A cert-authenticated client with no user identity still has to put
something in the password slot, since Git requires one for Basic
auth. Any non-JWT value is treated as that placeholder and ignored,
so the request proceeds with the agent alone:

  git clone https://<agent-role>:x@<warden-addr>/v1/...

For GitHub Enterprise Server:
  Configure github_url to point to your GHE instance API endpoint
  (e.g., https://github.example.com/api/v3). The Git host is derived
  automatically (e.g., https://github.example.com).

The role can be provided via the X-Warden-Role header, embedded in
the URL path (/github/role/{role}/gateway/{api-path}), carried in
the Basic Auth username (Git smart-HTTP requests only), or defaulted
by default_role. Precedence: X-Warden-Role > path role > Basic Auth
username > default_role.

Header-routed alternative: clients that want a URL without the
/v1/github/gateway/ prefix can send X-Warden-Provider: github (and
optionally X-Warden-Role) and let Warden synthesise the canonical
path from the literal upstream path. For Git, set both via
http.extraheader at clone time:

  git -c http.extraheader="X-Warden-Provider: github" \
      clone https://<role>:$JWT@<warden-addr>/<owner>/<repo>.git

http.extraheader persists into .git/config, so subsequent fetch/pull/push
carry the header automatically.

Configuration:
- github_url: GitHub API base URL (default: https://api.github.com)
- api_version: GitHub REST API version header (default: 2022-11-28)
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
