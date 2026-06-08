package httpproxy

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// defaultAcceptJSON is the Accept value injected when no spec or dispatch
// override is in force and Accept defaulting is not suppressed.
const defaultAcceptJSON = "application/json"

func (b *proxyBackend) handleGateway(ctx context.Context, req *logical.Request) {
	// Framework-side fields are atomic — read directly.
	timeout := b.Timeout()
	maxBody := b.MaxBodySize()
	// Provider-local fields still need the RLock.
	b.mu.RLock()
	providerURL := b.providerURL
	proxy := b.Proxy
	b.mu.RUnlock()

	credExtractor := b.spec.ExtractCredentials
	var dispatch Dispatch
	if b.spec.ResolveUpstream != nil {
		b.mu.RLock()
		state := b.extraState
		b.mu.RUnlock()
		if d, ok := b.spec.ResolveUpstream(req.HTTPRequest, providerURL, state); ok {
			dispatch = d
			if d.UpstreamURL != "" {
				providerURL = d.UpstreamURL
			}
			if d.ExtractCredentials != nil {
				credExtractor = d.ExtractCredentials
			}
			if d.MaxBodySize > 0 {
				maxBody = d.MaxBodySize
			}
		}
	}

	// Apply timeout if configured
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
		req.HTTPRequest = req.HTTPRequest.WithContext(ctx)
	}

	// Enforce max body size
	if maxBody <= 0 {
		maxBody = framework.DefaultMaxBodySize
	}
	req.HTTPRequest.Body = http.MaxBytesReader(req.ResponseWriter, req.HTTPRequest.Body, maxBody)

	// Extract credentials using provider-specific extractor.
	// Skip on stream-unauthenticated requests: core skipped credential
	// minting, so req.Credential is nil — the extractor would 401 a probe
	// that the backend has explicitly cleared for upstream pass-through
	// (e.g. Git smart-HTTP first probe → upstream WWW-Authenticate →
	// client retry with Basic Auth).
	var credHeaders map[string]string
	if !req.StreamUnauthenticated {
		var err error
		credHeaders, err = credExtractor(req)
		if err != nil {
			b.Logger.Warn("Failed to get credentials", logger.Err(err))
			http.Error(req.ResponseWriter, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	// Build target URL
	targetURL, err := buildTargetURL(providerURL, req.HTTPRequest.URL.Path, req.HTTPRequest.URL.RawQuery)
	if err != nil {
		b.Logger.Error("Failed to build target URL", logger.Err(err))
		http.Error(req.ResponseWriter, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Prepare request for proxying
	r := req.HTTPRequest
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		b.Logger.Error("Failed to parse target URL", logger.Err(err))
		http.Error(req.ResponseWriter, "Internal server error", http.StatusInternalServerError)
		return
	}
	r.URL = parsedURL
	r.Host = parsedURL.Host
	r.RequestURI = "" // Required for outgoing requests

	// Clean headers and inject credentials
	b.prepareHeaders(r, credHeaders, dispatch)

	b.Logger.Trace("Proxying request",
		logger.String("provider", b.spec.Name),
		logger.String("path", r.URL.Path),
		logger.String("method", r.Method),
	)

	// Forward the request (body streams through without buffering)
	proxy.ServeHTTP(req.ResponseWriter, r)
}

// buildTargetURL constructs the target URL from the gateway path.
func buildTargetURL(providerURL, path, rawQuery string) (string, error) {
	// Providers whose upstream is instance-specific (gitlab, kubernetes,
	// splunk, mcp, ...) ship an empty DefaultURL and require the operator
	// to configure one. Guard here so a request to an unconfigured mount fails
	// with a clear, logged error instead of forwarding to a schemeless URL
	// that surfaces as an opaque proxy-level 502.
	if providerURL == "" {
		return "", fmt.Errorf("upstream URL not configured")
	}
	apiPath, ok := PathAfterGateway(path)
	if !ok {
		return "", fmt.Errorf("invalid gateway path: %s", path)
	}
	// Preserve the client's path after "/gateway" verbatim, including whether it
	// ended in a slash. A bare ".../gateway" (empty suffix) targets the configured
	// upstream URL as-is; ".../gateway/" appends a slash. This lets a path-bearing
	// upstream such as https://mcp.slack.com/mcp be reached without a forced
	// trailing slash that strict servers 301-redirect; host-only upstreams are
	// unaffected since net/http sends an empty path as "/".

	if rawQuery != "" {
		return providerURL + apiPath + "?" + rawQuery, nil
	}
	return providerURL + apiPath, nil
}

// PathAfterGateway returns the portion of path that follows the first
// "/gateway" segment, with that segment stripped. Returns ok=false when no
// "/gateway" segment is present in the path. Exposed so providers
// implementing ResolveUpstream can extract the API-shaped path slice from
// req.URL.Path without re-implementing the strip rule.
func PathAfterGateway(path string) (string, bool) {
	idx := strings.Index(path, "/gateway")
	if idx == -1 {
		return "", false
	}
	return path[idx+len("/gateway"):], true
}

// resolveAcceptDefault returns the Accept value to inject when the client did
// not set one. Empty string means "do not inject anything."
//
// Precedence:
//  1. dispatch.Accept (non-empty) wins.
//  2. Otherwise, if dispatch.SkipDefaultAccept is set, suppress.
//  3. Otherwise, fall through to specDefault, defaulting to defaultAcceptJSON
//     when specDefault is empty.
func resolveAcceptDefault(specDefault string, dispatch Dispatch) string {
	if dispatch.Accept != "" {
		return dispatch.Accept
	}
	if dispatch.SkipDefaultAccept {
		return ""
	}
	if specDefault != "" {
		return specDefault
	}
	return defaultAcceptJSON
}

// prepareHeaders removes unwanted headers and injects credential + provider headers.
// The dispatch carries per-request overrides for Accept defaulting and dynamic-header
// injection; zero values mean "use the spec defaults."
func (b *proxyBackend) prepareHeaders(r *http.Request, credHeaders map[string]string, dispatch Dispatch) {
	// Read Connection header before removing it
	conn := r.Header.Get("Connection")

	// Remove base headers
	for _, h := range BaseHeadersToRemove {
		r.Header.Del(h)
	}

	// Remove provider-specific extra headers
	for _, h := range b.spec.ExtraHeadersToRemove {
		r.Header.Del(h)
	}

	// Handle Connection header's listed headers
	if conn != "" {
		for _, h := range strings.Split(conn, ",") {
			if h = strings.TrimSpace(h); h != "" {
				r.Header.Del(h)
			}
		}
	}

	// Inject credential headers
	for k, v := range credHeaders {
		r.Header.Set(k, v)
	}

	// Inject static default headers
	for k, v := range b.spec.DefaultHeaders {
		r.Header.Set(k, v)
	}

	// Inject dynamic headers as fallbacks — only set if the client didn't already
	// provide them. This differs from DefaultHeaders and credential headers which
	// always override. SkipDynamicHeaders lets per-request dispatches opt out.
	if b.spec.DynamicHeaders != nil && !dispatch.SkipDynamicHeaders {
		b.mu.RLock()
		state := b.extraState
		b.mu.RUnlock()
		for k, v := range b.spec.DynamicHeaders(state) {
			if r.Header.Get(k) == "" {
				r.Header.Set(k, v)
			}
		}
	}

	if r.Header.Get("Accept") == "" {
		if accept := resolveAcceptDefault(b.spec.DefaultAccept, dispatch); accept != "" {
			r.Header.Set("Accept", accept)
		}
	}

	// Set User-Agent if not already set
	if r.Header.Get("User-Agent") == "" {
		ua := "warden-" + b.spec.Name + "-proxy"
		if b.spec.UserAgent != "" {
			ua = b.spec.UserAgent
		}
		r.Header.Set("User-Agent", ua)
	}
}
