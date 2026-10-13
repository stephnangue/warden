// Package msgraph is the Microsoft Graph provider: one fixed upstream for every
// Graph workload — Microsoft 365 mail, calendar, Teams, SharePoint and OneDrive,
// Entra directory, Intune (deviceManagement), Planner, To Do and Security — with
// the token Warden minted for the role, typically a delegated on_behalf_of token
// for the user the agent acts for.
package msgraph

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/sdk/graphbatch"
	"github.com/stephnangue/warden/provider/sdk/httpproxy"
)

const (
	// DefaultGraphURL is the public-cloud Microsoft Graph endpoint.
	DefaultGraphURL = "https://graph.microsoft.com"

	// DefaultTimeout bounds a Graph call; large mail, drive and device listings can
	// be slow.
	DefaultTimeout = 60 * time.Second

	urlConfigKey = "graph_url"
)

// defaultGraphHosts are the Graph endpoints of the public and sovereign clouds.
// graph_url may name only one of them: the mount sends every user's delegated
// token there, so it must never be redirectable to an arbitrary host.
var defaultGraphHosts = []string{
	"graph.microsoft.com",
	"graph.microsoft.us",
	"dod-graph.microsoft.us",
	"microsoftgraph.chinacloudapi.cn",
}

var (
	errBatchNotSupported  = errors.New("Graph JSON batching ($batch) is not supported through Warden: send the requests individually")
	errUpstreamNotTrusted = errors.New("the configured graph_url is not a Microsoft Graph endpoint")
)

// Spec is the Microsoft Graph provider.
var Spec = newSpec(defaultGraphHosts)

// Factory creates a new Microsoft Graph provider backend.
var Factory = httpproxy.NewFactory(Spec)

// newSpec builds the provider for a fixed set of Graph hosts. The set is part of
// the spec, so it cannot change under a running mount; tests build their own spec
// to reach a local server.
func newSpec(hosts []string) *httpproxy.ProviderSpec {
	allowed := slices.Clone(hosts)
	checkURL := func(raw string) error { return checkGraphURL(raw, allowed) }

	// trusted is the last upstream the per-request check accepted, so the common
	// case — every request on a mount going to the same graph_url — compares a
	// string instead of re-parsing a URL.
	var trusted atomic.Pointer[string]

	return &httpproxy.ProviderSpec{
		Name:               "msgraph",
		DefaultURL:         DefaultGraphURL,
		URLConfigKey:       urlConfigKey,
		DefaultTimeout:     DefaultTimeout,
		ParseStreamBody:    true,
		UserAgent:          "warden-msgraph-proxy",
		HelpText:           msgraphBackendHelp,
		ExtractCredentials: extractGraphToken,
		ResolveUpstream:    resolveUpstream,
		RenderGatewayError: renderGraphError,

		// graph_url is checked where it is set — at mount time and on every config
		// write — and again on every request, so a value that reached storage some
		// other way still cannot carry a token off Graph.
		ValidateExtraConfig: func(conf map[string]any) error {
			if v, ok := conf[urlConfigKey].(string); ok && v != "" {
				return checkURL(v)
			}
			return nil
		},
		OnConfigWrite: func(d *framework.FieldData, state map[string]any) (map[string]any, error) {
			if v, ok := d.GetOk(urlConfigKey); ok {
				if s, _ := v.(string); s != "" {
					if err := checkURL(s); err != nil {
						return nil, err
					}
				}
			}
			return state, nil
		},
		// Runs in the gateway, after core has minted the request's credential: a
		// refused $batch still costs a mint on a cache miss, but never reaches Graph.
		RefuseRequest: func(r *http.Request, providerURL string, _ map[string]any) (int, error) {
			if last := trusted.Load(); last == nil || *last != providerURL {
				if checkURL(providerURL) != nil {
					return http.StatusInternalServerError, errUpstreamNotTrusted
				}
				trusted.Store(&providerURL)
			}
			if api, ok := httpproxy.PathAfterGateway(r.URL.Path); ok && graphbatch.IsBatchPath(api) {
				return http.StatusBadRequest, errBatchNotSupported
			}
			return 0, nil
		},
	}
}

// checkGraphURL accepts only an https origin on one of the allowed hosts: no
// path (the gateway path already carries the version), no credentials, query or
// fragment.
func checkGraphURL(raw string, allowed []string) error {
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil {
		return fmt.Errorf("%s: %w", urlConfigKey, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%s must use https", urlConfigKey)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return fmt.Errorf("%s must be a bare origin such as %s", urlConfigKey, DefaultGraphURL)
	}
	host := strings.ToLower(u.Hostname())
	if !slices.Contains(allowed, host) {
		return fmt.Errorf("%s must be a Microsoft Graph endpoint (%s)", urlConfigKey, strings.Join(allowed, ", "))
	}
	// Graph serves on 443 only. A port would not leave Graph, but it would make
	// the origin differ from the one Graph writes into its paging links.
	if u.Port() != "" && slices.Contains(defaultGraphHosts, host) {
		return fmt.Errorf("%s must not carry a port", urlConfigKey)
	}
	return nil
}

// extractGraphToken injects the minted token as a bearer. An azure_bearer_token
// is Warden's own Entra mint (on_behalf_of for delegated access, bearer_token for
// app-only); an oauth_bearer_token comes from the oauth2 or token_exchange
// drivers, e.g. a shared mailbox connected once through the authorization-code
// flow.
func extractGraphToken(req *logical.Request) (map[string]string, error) {
	if req.Credential == nil {
		return nil, fmt.Errorf("no credential available")
	}
	var token string
	switch req.Credential.Type {
	case credential.TypeAzureBearerToken:
		token = req.Credential.Data["access_token"]
	case credential.TypeOAuthBearerToken:
		token = req.Credential.Data["api_key"]
	default:
		return nil, fmt.Errorf("unsupported credential type for msgraph: %s", req.Credential.Type)
	}
	if token == "" {
		return nil, fmt.Errorf("credential missing token")
	}
	return map[string]string{"Authorization": "Bearer " + token}, nil
}

// resolveUpstream leaves binary transfers alone: an upload (PUT) or a download
// (/content, /$value) carries no JSON for policy to read, and parsing it — or
// defaulting Accept to JSON — would break it.
func resolveUpstream(r *http.Request, _ string, _ map[string]any) (httpproxy.Dispatch, bool) {
	api, ok := httpproxy.PathAfterGateway(r.URL.Path)
	if !ok {
		return httpproxy.Dispatch{}, false
	}
	if r.Method == http.MethodPut || isBinaryPath(api) {
		return httpproxy.Dispatch{BypassBodyParsing: true, SkipDefaultAccept: true}, true
	}
	return httpproxy.Dispatch{}, false
}

func isBinaryPath(api string) bool {
	p := strings.TrimRight(api, "/")
	return hasSuffixFold(p, "/content") || hasSuffixFold(p, "/$value")
}

// hasSuffixFold is strings.HasSuffix ignoring ASCII case, without allocating.
func hasSuffixFold(s, suffix string) bool {
	return len(s) >= len(suffix) && strings.EqualFold(s[len(s)-len(suffix):], suffix)
}

const msgraphBackendHelp = `
The Microsoft Graph provider proxies requests to Microsoft Graph — every Graph
workload: Microsoft 365 mail, calendar, Teams, SharePoint and OneDrive, Entra
directory, Intune (deviceManagement), Planner, To Do and Security — injecting the
token Warden minted for the role. Bind the role to an azure_bearer_token spec with
mint_method=on_behalf_of to act as the user the agent presents (their Entra access
token, on the mount's user_auth_path); an app-only spec acts as the app.

The gateway path format is:
  /msgraph/gateway/{version}/{resource}

Examples:
  /msgraph/gateway/v1.0/me
  /msgraph/gateway/v1.0/me/messages?$top=10&$select=subject,from
  /msgraph/gateway/v1.0/me/events
  /msgraph/gateway/v1.0/me/chats
  /msgraph/gateway/v1.0/sites/{site-id}/drive/root/children
  /msgraph/gateway/v1.0/deviceManagement/managedDevices
  /msgraph/gateway/beta/deviceManagement/deviceCompliancePolicies

The role can be provided via the X-Warden-Role header, or embedded in the URL
path:
  /msgraph/role/{role}/gateway/{version}/{resource}

Request body parsing is enabled, so policies can evaluate JSON body fields (for
example sendMail recipients). Graph JSON batching ($batch) is refused: a batch
would carry requests a path policy never sees.

Configuration:
- graph_url: Graph endpoint (default https://graph.microsoft.com; one of the
  Microsoft Graph hosts of the public or sovereign clouds)
- max_body_size: Maximum request body size (default: 10MB, max: 100MB)
- timeout: Request timeout duration (default: 60s)
- auto_auth_path: Auth mount path for implicit authentication of the agent
- user_auth_path / user_auth_role: Auth mount (and role) the user's Entra access
  token is validated against, for on_behalf_of
- default_role: Fallback role when not specified in the URL path
`
