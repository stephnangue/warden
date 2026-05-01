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

func (b *proxyBackend) handleGateway(ctx context.Context, req *logical.Request) {
	// Snapshot mutable fields under read lock to avoid races with config writes
	b.mu.RLock()
	timeout := b.Timeout
	maxBody := b.MaxBodySize
	providerURL := b.providerURL
	proxy := b.Proxy
	b.mu.RUnlock()

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

	// Extract credentials using provider-specific extractor
	credHeaders, err := b.spec.ExtractCredentials(req)
	if err != nil {
		b.Logger.Warn("Failed to get credentials", logger.Err(err))
		http.Error(req.ResponseWriter, "Unauthorized", http.StatusUnauthorized)
		return
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
	b.prepareHeaders(r, credHeaders)

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
	gatewayIdx := strings.Index(path, "/gateway")
	if gatewayIdx == -1 {
		return "", fmt.Errorf("invalid gateway path: %s", path)
	}

	// Extract path after "/gateway"
	apiPath := path[gatewayIdx+8:] // len("/gateway") = 8
	if apiPath == "" || apiPath == "/" {
		apiPath = "/"
	}

	if rawQuery != "" {
		return providerURL + apiPath + "?" + rawQuery, nil
	}
	return providerURL + apiPath, nil
}

// prepareHeaders removes unwanted headers and injects credential + provider headers.
func (b *proxyBackend) prepareHeaders(r *http.Request, credHeaders map[string]string) {
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
	// always override.
	if b.spec.DynamicHeaders != nil {
		b.mu.RLock()
		state := b.extraState
		b.mu.RUnlock()
		for k, v := range b.spec.DynamicHeaders(state) {
			if r.Header.Get(k) == "" {
				r.Header.Set(k, v)
			}
		}
	}

	// Set Accept header if not already set
	accept := "application/json"
	if b.spec.DefaultAccept != "" {
		accept = b.spec.DefaultAccept
	}
	if r.Header.Get("Accept") == "" {
		r.Header.Set("Accept", accept)
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
