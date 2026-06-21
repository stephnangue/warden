package rest

import (
	"fmt"
	"net/http"
	"net/textproto"
	"time"

	"golang.org/x/net/http/httpguts"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/sdk/httpproxy"
)

// DefaultRESTTimeout is the default request timeout for proxied REST calls.
const DefaultRESTTimeout = 30 * time.Second

const (
	defaultTokenHeader = "Authorization"
	defaultTokenPrefix = "Bearer "
)

// Spec defines the generic REST provider for the httpproxy framework.
//
// Unlike service-specific providers (openai, slack, …) that hard-code one
// upstream and one auth-header convention, the rest provider lets the operator
// point a mount at any single-token REST API purely through config:
//
//   - base_url      the upstream API base URL
//   - token_header  the header the brokered token is injected into (default Authorization)
//   - token_prefix  prepended to the token (default "Bearer "; set "" for a raw token)
//   - headers       additional static headers injected on every proxied request
//
// The token value itself is brokered per request from the credential subsystem
// exactly like every other provider; only its placement is configurable.
var Spec = &httpproxy.ProviderSpec{
	Name:            "rest",
	DefaultURL:      "", // operator must configure base_url
	URLConfigKey:    "base_url",
	DefaultTimeout:  DefaultRESTTimeout,
	ParseStreamBody: false,
	UserAgent:       "warden-rest-proxy",
	HelpText:        restBackendHelp,

	// Defensive default. At request time ResolveUpstream always supplies a
	// state-derived extractor, so this is never consulted; it only guards
	// against a nil-func call if that ever changes.
	ExtractCredentials: tokenExtractor(defaultTokenHeader, defaultTokenPrefix, nil),

	ExtraConfigFields: map[string]*framework.FieldSchema{
		"token_header": {
			Type:        framework.TypeString,
			Default:     defaultTokenHeader,
			Description: "Header name the brokered token is injected into (default: Authorization)",
		},
		"token_prefix": {
			Type:        framework.TypeString,
			Default:     defaultTokenPrefix,
			Description: `Prefix prepended to the token (e.g. "Bearer "); set to "" for a raw token in the header`,
		},
		"headers": {
			Type:        framework.TypeKVPairs,
			Description: "Additional static headers (name=value) injected on every proxied request; these override client-supplied headers of the same name",
		},
	},

	// Single state-aware injection point: token header + static headers are
	// returned together by the credential extractor so both are applied with
	// override (Header.Set) semantics — operator-pinned headers cannot be
	// suppressed by a client sending the same header name.
	ResolveUpstream: func(_ *http.Request, _ string, state map[string]any) (httpproxy.Dispatch, bool) {
		header := stateString(state, "token_header", defaultTokenHeader)
		prefix := statePrefix(state)
		static := stateHeaders(state)
		return httpproxy.Dispatch{ExtractCredentials: tokenExtractor(header, prefix, static)}, true
	},

	OnConfigWrite: func(d *framework.FieldData, state map[string]any) (map[string]any, error) {
		var headerName string
		hasHeaderName := false
		if v, ok := d.GetOk("token_header"); ok {
			headerName = v.(string)
			hasHeaderName = true
		}
		var headers map[string]string
		if v, ok := d.GetOk("headers"); ok {
			headers = coerceStringMap(v)
		}
		if err := validateRESTConfig(headerName, hasHeaderName, headers); err != nil {
			return nil, err
		}

		if hasHeaderName {
			state["token_header"] = headerName
		}
		// token_prefix is stored whenever provided (GetOk reports present even
		// for an explicit ""), which is how a raw-token header is distinguished
		// from the unset default.
		if v, ok := d.GetOk("token_prefix"); ok {
			state["token_prefix"] = v.(string)
		}
		if _, ok := d.GetOk("headers"); ok {
			state["headers"] = headers
		}
		return state, nil
	},

	OnConfigRead: func(state map[string]any) map[string]any {
		return map[string]any{
			"token_header": stateString(state, "token_header", defaultTokenHeader),
			"token_prefix": statePrefix(state),
			"headers":      stateHeaders(state),
		}
	},

	OnInitialize: func(config map[string]any, state map[string]any) map[string]any {
		if v, ok := config["token_header"].(string); ok && v != "" {
			state["token_header"] = v
		}
		// Preserve an explicit empty prefix (raw token); only the absence of the
		// key falls through to the "Bearer " default at read time.
		if v, ok := config["token_prefix"]; ok {
			if s, ok := v.(string); ok {
				state["token_prefix"] = s
			}
		}
		if h := coerceStringMap(config["headers"]); len(h) > 0 {
			state["headers"] = h
		}
		return state
	},

	ValidateExtraConfig: func(conf map[string]any) error {
		headerName, hasHeaderName := conf["token_header"].(string)
		return validateRESTConfig(headerName, hasHeaderName, coerceStringMap(conf["headers"]))
	},
}

// Factory creates a new generic REST provider backend.
var Factory = httpproxy.NewFactory(Spec)

// tokenExtractor returns a credential extractor that injects the brokered token
// into header (prefixed with prefix) alongside any static headers. The token
// entry is written last so it wins a key collision with a static header.
//
// Both TypeAPIKey and TypeOAuthBearerToken are accepted: each stores its token
// in Data["api_key"] (the oauth2 source maps its access token there), so one
// path serves static keys, dynamically minted keys, and OAuth2 bearer tokens.
func tokenExtractor(header, prefix string, static map[string]string) httpproxy.CredentialExtractor {
	return func(req *logical.Request) (map[string]string, error) {
		if req.Credential == nil {
			return nil, fmt.Errorf("no credential available")
		}
		if req.Credential.Type != credential.TypeAPIKey && req.Credential.Type != credential.TypeOAuthBearerToken {
			return nil, fmt.Errorf("unsupported credential type: %s", req.Credential.Type)
		}
		apiKey := req.Credential.Data["api_key"]
		if apiKey == "" {
			return nil, fmt.Errorf("credential missing api_key field")
		}
		// Canonicalize header names so a static header that differs from the
		// token header only in case collapses onto the same map key rather than
		// surfacing as two entries that the downstream Header.Set would apply in
		// nondeterministic (map-iteration) order. The token is written last so it
		// always wins a collision.
		headers := make(map[string]string, len(static)+1)
		for k, v := range static {
			headers[textproto.CanonicalMIMEHeaderKey(k)] = v
		}
		headers[textproto.CanonicalMIMEHeaderKey(header)] = prefix + apiKey
		return headers, nil
	}
}

// stateString returns the string value at key, defaulting when the key is
// absent or empty.
func stateString(state map[string]any, key, def string) string {
	if s, _ := state[key].(string); s != "" {
		return s
	}
	return def
}

// statePrefix returns the configured token prefix. An absent token_prefix key
// yields the "Bearer " default; a key that is present — even an empty string —
// is honored verbatim, so token_prefix="" produces a raw token in the header.
func statePrefix(state map[string]any) string {
	if v, ok := state["token_prefix"]; ok {
		s, _ := v.(string)
		return s
	}
	return defaultTokenPrefix
}

// stateHeaders returns the configured static headers, coercing the
// map[string]any shape that JSON-decoded persisted config yields back into
// map[string]string.
func stateHeaders(state map[string]any) map[string]string {
	return coerceStringMap(state["headers"])
}

// coerceStringMap normalizes a header map that may arrive as map[string]string
// (fresh from FieldData) or map[string]any (after a storage JSON round-trip)
// into map[string]string. Returns nil for any other shape.
func coerceStringMap(v any) map[string]string {
	switch m := v.(type) {
	case map[string]string:
		return m
	case map[string]any:
		out := make(map[string]string, len(m))
		for k, val := range m {
			if s, ok := val.(string); ok {
				out[k] = s
			}
		}
		return out
	}
	return nil
}

// validateRESTConfig rejects header names/values that the HTTP layer would
// later refuse to write — using the same validators net/http applies at
// request time (httpguts), so an invalid header is caught at config time
// instead of 502-ing every proxied request. An empty token_header is allowed
// and falls back to the Authorization default.
func validateRESTConfig(tokenHeader string, hasTokenHeader bool, headers map[string]string) error {
	if hasTokenHeader && tokenHeader != "" && !httpguts.ValidHeaderFieldName(tokenHeader) {
		return fmt.Errorf("invalid token_header %q: not a valid HTTP header name", tokenHeader)
	}
	for k, v := range headers {
		if !httpguts.ValidHeaderFieldName(k) {
			return fmt.Errorf("invalid header name %q: not a valid HTTP header name", k)
		}
		if !httpguts.ValidHeaderFieldValue(v) {
			return fmt.Errorf("invalid value for header %q: not a valid HTTP header value", k)
		}
	}
	return nil
}

const restBackendHelp = `
The REST provider proxies requests to any single-token REST API with automatic
credential injection. A single provider type fronts arbitrary upstreams by
mounting multiple instances with different configuration.

Warden performs implicit authentication on every request, obtains the upstream
token from the credential manager, and injects it into the configured header.
The token value is never stored in the mount configuration.

Configuration:
- base_url:       Upstream API base URL (required)
- token_header:   Header the brokered token is injected into (default: Authorization)
- token_prefix:   Prefix prepended to the token (default: "Bearer "; set "" for a raw token)
- headers:        Additional static headers (name=value) injected on every request
- max_body_size:  Maximum request body size (default: 10MB, max: 100MB)
- timeout:        Request timeout duration (default: 30s)
- auto_auth_path: Auth mount path for implicit authentication (e.g. 'auth/jwt/')
- default_role:   Fallback role when not specified in the URL path
- tls_skip_verify, ca_data: TLS options for the upstream connection

The gateway path format is:
  /<mount>/gateway/{api-path}
  /<mount>/role/{role}/gateway/{api-path}

Supported credential types: api_key (apikey/grafana/honeycomb/elastic sources)
and oauth_bearer_token (oauth2 source). Both carry the token in the api_key field.
`
