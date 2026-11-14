// Package gws is the Google Workspace provider: Gmail, Drive,
// Calendar, Docs, Sheets, Slides, Forms, Tasks, Chat, People and the Admin SDK,
// each on its own googleapis.com host, called with the token Warden minted for
// the role — typically a gcp_delegated_token acting as the user the agent
// presents, through domain-wide delegation.
//
// The host is named in the gateway path, /gateway/<host>/<path>, so policy sees
// which API a request reaches. A mount sends user tokens only to the hosts its
// allowlist names, and refuses what a path policy cannot see into: batch
// requests and credentials carried in the request itself.
package gws

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
	"github.com/stephnangue/warden/provider/sdk/httpproxy"
)

const (
	// DefaultTimeout bounds one call. A resumable upload sends each chunk as its
	// own call, so it bounds a chunk, not the whole upload.
	DefaultTimeout = 60 * time.Second

	// urlConfigKey names a stand-in upstream for the end-to-end suite. In any
	// other build it is refused: the host a request reaches is the one its path
	// names.
	urlConfigKey = "gws_url"

	googleAPIsSuffix = ".googleapis.com"
)

// defaultAllowedHostSuffixes are the Workspace API hosts a mount sends user
// tokens to when its config names none. Narrower than the gcp provider's
// googleapis.com: these tokens act as a person.
var defaultAllowedHostSuffixes = []string{
	".www.googleapis.com", // Drive v3, Calendar v3, and upload sessions
	".gmail.googleapis.com",
	".drive.googleapis.com",
	".docs.googleapis.com",
	".sheets.googleapis.com",
	".slides.googleapis.com",
	".forms.googleapis.com",
	".tasks.googleapis.com",
	".chat.googleapis.com",
	".people.googleapis.com",
	".admin.googleapis.com",
}

// defaultOrigins maps each default host to its upstream origin, built once so the
// common request allocates nothing to address its upstream.
var defaultOrigins = func() map[string]string {
	m := make(map[string]string, len(defaultAllowedHostSuffixes))
	for _, suffix := range defaultAllowedHostSuffixes {
		host := suffix[1:]
		m[host] = "https://" + host
	}
	return m
}()

var (
	errNoHost             = errors.New("the gateway path must name a Google API host and a path: /gateway/<host>/<path>")
	errHostNotAllowed     = errors.New("this mount does not send tokens to that host; see allowed_host_suffixes")
	errUpstreamNotTrusted = errors.New("the configured " + urlConfigKey + " is not an upstream this build may reach")
	errBatchNotSupported  = errors.New("Google batch requests are not supported through Warden: send the requests individually")
	errCredentialInQuery  = errors.New("the query may not carry a credential, a billing project or a system parameter that restates the request " +
		"(access_token, oauth_token, key, userProject, $httpHeaders, ...): Warden supplies the user's token")
	errBodyNotJSON = errors.New("a request body outside /upload/ paths must be JSON, labelled by one Content-Type: application/json")
	errBodyOnRead  = errors.New("a GET, HEAD or DELETE request may not carry a body")
)

// Spec is the Google Workspace provider.
var Spec = newSpec(buildTagHosts)

// Factory creates a new Google Workspace provider backend.
var Factory = httpproxy.NewFactory(Spec)

// newSpec builds the provider. overrideHosts are the hosts gws_url
// may name — none outside the end-to-end build; tests build their own spec.
func newSpec(overrideHosts []string) *httpproxy.ProviderSpec {
	allowedOverride := slices.Clone(overrideHosts)
	checkURL := func(raw string) error { return checkOverrideURL(raw, allowedOverride) }

	// trusted is the last override the per-request check accepted, so a mount
	// pointed at a stand-in compares a string rather than re-parsing a URL.
	var trusted atomic.Pointer[string]

	return &httpproxy.ProviderSpec{
		Name:               "gws",
		DefaultURL:         "",
		URLConfigKey:       urlConfigKey,
		DefaultTimeout:     DefaultTimeout,
		ParseStreamBody:    true,
		UserAgent:          "warden-gws-proxy",
		HelpText:           gwsBackendHelp,
		ExtractCredentials: extractGoogleToken,
		// A method override would have Google run a method other than the one
		// policy authorized; the API key and billing project headers would have
		// the caller's own credential or project ride on the user's token.
		ExtraHeadersToRemove: []string{
			"X-HTTP-Method-Override",
			"X-HTTP-Method",
			"X-Method-Override",
			"X-Goog-Api-Key",
			"X-Goog-User-Project",
		},
		ResolveUpstream:      resolveUpstream,
		RenderGatewayError:   renderGoogleError,
		RewriteResponse:      uploadRequest,
		ModifyResponse:       rewriteUploadSession,
		RewriteWithoutPrefix: true,
		ExtraConfigFields:    hostConfigFields,
		OnConfigRead: func(state map[string]any) map[string]any {
			return map[string]any{framework.HostAllowlistKey: configuredAllowlist(state)}
		},
		OnInitialize: func(config map[string]any, state map[string]any) map[string]any {
			// Checked at mount and on every write; a stored value that no longer
			// parses falls back to the default rather than to no restriction.
			if entries, err := parseAllowlist(config[framework.HostAllowlistKey]); err == nil {
				state[framework.HostAllowlistKey] = entries
			}
			return state
		},
		ValidateExtraConfig: func(conf map[string]any) error {
			if v, ok := conf[urlConfigKey].(string); ok && v != "" {
				if err := checkURL(v); err != nil {
					return err
				}
			}
			_, err := parseAllowlist(conf[framework.HostAllowlistKey])
			return err
		},
		OnConfigWrite: func(d *framework.FieldData, state map[string]any) (map[string]any, error) {
			if v, ok := d.GetOk(urlConfigKey); ok {
				if s, _ := v.(string); s != "" {
					if err := checkURL(s); err != nil {
						return nil, err
					}
				}
			}
			if v, ok := d.GetOk(framework.HostAllowlistKey); ok {
				entries, err := parseAllowlist(v)
				if err != nil {
					return nil, err
				}
				state[framework.HostAllowlistKey] = entries
			}
			return state, nil
		},
		// Runs in the gateway after core has minted the request's credential: a
		// refused request still costs a mint on a cache miss, but nothing reaches
		// Google.
		RefuseRequest: func(r *http.Request, providerURL string, state map[string]any) (int, error) {
			api, _ := httpproxy.PathAfterGateway(r.URL.Path)
			host, rest := splitHost(api)
			if host == "" || rest == "" || rest == "/" {
				return http.StatusBadRequest, errNoHost
			}
			// A default host is a valid hostname by construction.
			if _, known := defaultOrigins[host]; !known {
				if err := framework.ValidateTargetHost(host); err != nil {
					return http.StatusBadRequest, err
				}
			}
			if !framework.HostAllowed(host, allowlist(state)) {
				return http.StatusForbidden, errHostNotAllowed
			}
			if !isOrigin(providerURL, host) {
				if last := trusted.Load(); last == nil || *last != providerURL {
					if checkURL(providerURL) != nil {
						return http.StatusInternalServerError, errUpstreamNotTrusted
					}
					// A copy, so only this branch moves a string to the heap.
					accepted := providerURL
					trusted.Store(&accepted)
				}
			}
			if isBatchPath(rest) {
				return http.StatusBadRequest, errBatchNotSupported
			}
			if queryCarriesCredential(r.URL.RawQuery) {
				return http.StatusBadRequest, errCredentialInQuery
			}
			// Policy conditions read a JSON body, so no other body goes to Google
			// unread: core parses none on a read, nor one of another media type —
			// protobuf, text, or anything Google may decode that Warden cannot. A
			// form, which core does parse, is refused too: Workspace methods take
			// JSON, and how Google reads a form body is not Warden's to guess. An
			// upload's body is media, which no policy reads.
			if r.ContentLength != 0 && !isUploadPath(rest) {
				switch r.Method {
				case http.MethodGet, http.MethodHead, http.MethodDelete:
					return http.StatusBadRequest, errBodyOnRead
				}
				if !labelledJSON(r.Header) {
					return http.StatusUnsupportedMediaType, errBodyNotJSON
				}
			}
			return 0, nil
		},
	}
}

// extractGoogleToken injects the minted token as a bearer: a gcp_delegated_token
// acting as the user, or a gcp_access_token for a service account granted a
// Workspace admin role directly.
func extractGoogleToken(req *logical.Request) (map[string]string, error) {
	if req.Credential == nil {
		return nil, fmt.Errorf("no credential available")
	}
	switch req.Credential.Type {
	case credential.TypeGCPDelegatedToken, credential.TypeGCPAccessToken:
	default:
		return nil, fmt.Errorf("unsupported credential type for gws: %s", req.Credential.Type)
	}
	token := req.Credential.Data["access_token"]
	if token == "" {
		return nil, fmt.Errorf("credential missing access_token")
	}
	return map[string]string{"Authorization": "Bearer " + token}, nil
}

// resolveUpstream addresses the host the path names and drops that segment, so
// Google receives its own path. It names an upstream only for a host the mount
// allows: anything else is left unaddressed and fails closed even were the
// refusal above to miss it. Uploads and media downloads are binary and keep
// their own Accept; the body of a GET is never parsed anyway, so a download is
// recognised on GET alone — alt=media is the caller's to add, and must not stop
// policy reading the JSON body of a write.
//
// Pure and cheap: it runs up to three times a request.
func resolveUpstream(r *http.Request, providerURL string, state map[string]any) (httpproxy.Dispatch, bool) {
	api, ok := httpproxy.PathAfterGateway(r.URL.Path)
	if !ok {
		return httpproxy.Dispatch{}, false
	}
	host, rest := splitHost(api)
	var d httpproxy.Dispatch
	if isUploadPath(rest) {
		d.BypassBodyParsing = true
		d.SkipDefaultAccept = true
	} else if r.Method == http.MethodGet && hasQueryPair(r.URL.RawQuery, "alt", "media") {
		d.SkipDefaultAccept = true
	}
	if host == "" || !framework.HostAllowed(host, allowlist(state)) {
		return d, true
	}
	if origin, ok := defaultOrigins[host]; ok && providerURL == "" {
		// A default host is a valid hostname by construction: the common request
		// pays for neither the hostname check nor an origin string.
		d.UpstreamURL, d.DropSegments = origin, 1
		return d, true
	}
	if framework.ValidateTargetHost(host) != nil {
		return d, true
	}
	if providerURL != "" {
		// The end-to-end stand-in receives the whole path, host segment first, so
		// it can tell which API was addressed.
		d.UpstreamURL = providerURL
	} else {
		d.UpstreamURL, d.DropSegments = "https://"+host, 1
	}
	return d, true
}

// splitHost splits "/<host>/<rest>" into the host and "/<rest>" ("" when the
// path names only a host).
func splitHost(api string) (host, rest string) {
	p, ok := strings.CutPrefix(api, "/")
	if !ok {
		return "", ""
	}
	if i := strings.IndexByte(p, '/'); i >= 0 {
		return p[:i], p[i:]
	}
	return p, ""
}

// labelledJSON reports whether a request carries exactly one Content-Type, a
// single well-formed media type that core parses as JSON. Core reads the first
// label, the media type before ';', lowercased and trimmed; Google sees the header
// as sent. So whatever the two could read apart is refused rather than guessed at:
// a second Content-Type, a list in one ("…form-urlencoded, application/x+json"
// ends in +json, and a list can hide after a parameter), a byte ToLower folds into
// ASCII or TrimSpace drops, and no label at all, which core takes for JSON.
// Allocates nothing.
func labelledJSON(h http.Header) bool {
	labels := h["Content-Type"]
	return len(labels) == 1 &&
		logical.IsMediaTypeLabel(labels[0]) &&
		logical.IsJSONMediaType(logical.BodyMediaType(labels[0]))
}

// isOrigin reports whether providerURL is exactly https://<host>, without
// allocating.
func isOrigin(providerURL, host string) bool {
	rest, ok := strings.CutPrefix(providerURL, "https://")
	return ok && rest == host
}

// headSegments returns the first two segments of an API path as a lenient front
// end might read them: a backslash taken for a slash, slashes run together, a
// segment's ;parameters dropped. Dot segments never get here: core refuses them
// first. Allocates only when the path holds a backslash.
func headSegments(rest string) (first, second string) {
	if strings.IndexByte(rest, '\\') >= 0 {
		rest = strings.ReplaceAll(rest, `\`, "/")
	}
	first, rest = nextSegment(rest)
	second, _ = nextSegment(rest)
	return dropParams(first), dropParams(second)
}

// nextSegment returns the first non-empty segment of p and what follows it.
func nextSegment(p string) (seg, rest string) {
	p = strings.TrimLeft(p, "/")
	seg, rest, _ = strings.Cut(p, "/")
	return seg, rest
}

func dropParams(seg string) string {
	seg, _, _ = strings.Cut(seg, ";")
	return seg
}

// isUploadPath reports whether an API path addresses a media upload: Google
// serves uploads under /upload/ and resumable sessions under /resumable/upload/.
func isUploadPath(rest string) bool {
	first, second := headSegments(rest)
	return strings.EqualFold(first, "upload") ||
		(strings.EqualFold(first, "resumable") && strings.EqualFold(second, "upload"))
}

// isBatchPath reports whether an API path addresses a batch endpoint — /batch,
// /batch/drive/v3, /batch/gmail/v1, /$batch and the like — in any case, with a
// backslash for a slash or ;parameters on the segment. A batch is a multipart
// body of requests a path policy never sees. Methods named batchDelete or
// :batchUpdate are ordinary paths policy does see, and are left alone.
func isBatchPath(rest string) bool {
	first, _ := headSegments(rest)
	return strings.EqualFold(first, "batch") || strings.EqualFold(first, "$batch")
}

// Query parameters Google reads as credentials, billing or a rewrite of the
// request itself. Google takes each system parameter with or without a leading
// "$", so a key is compared with it removed.
var refusedQueryKeys = []string{
	"access_token", "oauth_token", "bearer_token", "key", // a credential beside the user's token
	"userProject", // the project billed, as X-Goog-User-Project
}

// allowedSystemParams are the "$" system parameters a client may send: they shape
// the response, not the request. Any other "$" key — $httpHeaders, $httpMethod,
// $req, $ct — could restate the request's headers, method or body past policy.
var allowedSystemParams = []string{"$.xgafv", "$alt", "$fields", "$prettyPrint"}

// queryCarriesCredential reports whether a raw query carries what the request
// must not: a credential of its own, a billing project, or a system parameter
// that rewrites the request. Keys are compared as Google reads them — decoded,
// any case.
func queryCarriesCredential(rawQuery string) bool {
	for rawQuery != "" {
		var pair string
		pair, rawQuery, _ = strings.Cut(rawQuery, "&")
		key, _, _ := strings.Cut(pair, "=")
		if strings.ContainsAny(key, "%+") {
			if k, err := url.QueryUnescape(key); err == nil {
				key = k
			}
		}
		if strings.HasPrefix(key, "$") && !containsFold(allowedSystemParams, key) {
			return true
		}
		if containsFold(refusedQueryKeys, key) {
			return true
		}
	}
	return false
}

// containsFold reports whether list holds s, ignoring ASCII case.
func containsFold(list []string, s string) bool {
	for _, item := range list {
		if strings.EqualFold(item, s) {
			return true
		}
	}
	return false
}

// hasQueryPair reports whether a raw query carries key=value exactly, without
// allocating.
func hasQueryPair(rawQuery, key, value string) bool {
	for rawQuery != "" {
		var pair string
		pair, rawQuery, _ = strings.Cut(rawQuery, "&")
		if k, v, ok := strings.Cut(pair, "="); ok && k == key && v == value {
			return true
		}
	}
	return false
}

const gwsBackendHelp = `
The Google Workspace provider proxies requests to the Google Workspace APIs —
Gmail, Drive, Calendar, Docs, Sheets, Slides, Forms, Tasks, Chat, People and the
Admin SDK — injecting the token Warden minted for the role. Bind the role to a
gcp_delegated_token spec (mint_method=delegated_access_token) to act as the user
the agent presents, through domain-wide delegation.

The gateway path names the Google API host, then its path:
  /gws/gateway/{host}/{api-path}

Examples:
  /gws/gateway/gmail.googleapis.com/gmail/v1/users/me/messages
  /gws/gateway/www.googleapis.com/drive/v3/files
  /gws/gateway/www.googleapis.com/calendar/v3/calendars/primary/events
  /gws/gateway/docs.googleapis.com/v1/documents/{id}

The role can be provided via the X-Warden-Role header, or embedded in the URL
path:
  /gws/role/{role}/gateway/{host}/{api-path}

Request body parsing is enabled, so policies can evaluate JSON body fields —
except on upload paths (/upload/, /resumable/upload/), whose bodies are media
and are not parsed: policy there sees the path and query only. Refused: Google
batch requests (a batch carries requests a path policy never sees), credentials
or a billing project in the query (access_token, oauth_token, key, userProject),
"$" system parameters other than $alt, $fields, $prettyPrint and $.xgafv, and
method-override and API-key headers. Resumable upload sessions are pointed back
at Warden, which needs the protected-resource resource_url.

Configuration:
- allowed_host_suffixes: hosts tokens may be sent to, each with a leading dot,
  all under .googleapis.com (default: the Workspace API hosts)
- max_body_size: Maximum request body size, which bounds an upload chunk
  (default: 10MB, max: 100MB)
- timeout: Request timeout duration, per call and per upload chunk (default: 60s)
- auto_auth_path: Auth mount path for implicit authentication of the agent
- user_auth_path: Auth mount the user's identity is validated against
- default_role: Fallback role when not specified in the URL path
`
