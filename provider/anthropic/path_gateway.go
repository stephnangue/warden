package anthropic

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// anthropicAPIVersionHeader is the required Anthropic API version
const anthropicAPIVersionHeader = "2023-06-01"

// Headers to remove before proxying
var headersToRemove = []string{
	// Security headers (will be replaced with Anthropic API key)
	"Authorization",
	"X-Warden-Token",
	"X-Warden-Role",
	// Anthropic-specific headers (will be injected from credential data)
	"x-api-key",
	"anthropic-version",
	// Hop-by-hop headers
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
	// Proxy headers
	"X-Forwarded-For",
	"X-Forwarded-Host",
	"X-Forwarded-Proto",
	"X-Forwarded-Port",
	"X-Real-Ip",
	"Forwarded",
}

func (b *anthropicBackend) handleGateway(ctx context.Context, req *logical.Request) {
	// Apply timeout if configured
	if b.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, b.Timeout)
		defer cancel()
		req.HTTPRequest = req.HTTPRequest.WithContext(ctx)
	}

	// Enforce max body size
	maxBody := b.MaxBodySize
	if maxBody <= 0 {
		maxBody = framework.DefaultMaxBodySize
	}
	req.HTTPRequest.Body = http.MaxBytesReader(req.ResponseWriter, req.HTTPRequest.Body, maxBody)

	// Get Anthropic credential (API key)
	apiKey, err := b.getAnthropicCredential(req)
	if err != nil {
		b.Logger.Warn("Failed to get Anthropic API key", logger.Err(err))
		http.Error(req.ResponseWriter, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Build target URL
	targetURL, err := b.buildTargetURL(req.HTTPRequest.URL.Path, req.HTTPRequest.URL.RawQuery)
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

	// Clean headers and inject Anthropic credentials
	b.prepareHeaders(r, apiKey)

	b.Logger.Trace("Proxying Anthropic request",
		logger.String("path", r.URL.Path),
		logger.String("method", r.Method),
		logger.Bool("has_key", apiKey != ""),
	)

	// Forward the request (body streams through without buffering)
	b.Proxy.ServeHTTP(req.ResponseWriter, r)
}

// getAnthropicCredential extracts the Anthropic API key from the credential
func (b *anthropicBackend) getAnthropicCredential(req *logical.Request) (apiKey string, err error) {
	if req.Credential == nil {
		return "", fmt.Errorf("no credential available")
	}

	if req.Credential.Type != credential.TypeAIAPIKey {
		return "", fmt.Errorf("unsupported credential type: %s", req.Credential.Type)
	}

	apiKey = req.Credential.Data["api_key"]
	if apiKey == "" {
		return "", fmt.Errorf("credential missing api_key field")
	}

	return apiKey, nil
}

// buildTargetURL constructs the target Anthropic API URL from the gateway path
func (b *anthropicBackend) buildTargetURL(path, rawQuery string) (string, error) {
	// Find gateway path marker
	gatewayIdx := strings.Index(path, "/gateway")
	if gatewayIdx == -1 {
		return "", fmt.Errorf("invalid gateway path: %s", path)
	}

	// Extract path after "/gateway"
	anthropicPath := path[gatewayIdx+8:] // len("/gateway") = 8
	if anthropicPath == "" || anthropicPath == "/" {
		anthropicPath = "/"
	}

	if rawQuery != "" {
		return b.anthropicURL + anthropicPath + "?" + rawQuery, nil
	}
	return b.anthropicURL + anthropicPath, nil
}

// prepareHeaders removes unwanted headers and injects the Anthropic credentials
func (b *anthropicBackend) prepareHeaders(r *http.Request, apiKey string) {
	// Read Connection header before removing it
	conn := r.Header.Get("Connection")

	// Remove headers in single pass
	for _, h := range headersToRemove {
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

	// Inject the Anthropic API key using x-api-key header
	if apiKey != "" {
		r.Header.Set("x-api-key", apiKey)
	}

	// Inject the required anthropic-version header
	r.Header.Set("anthropic-version", anthropicAPIVersionHeader)

	// Set Accept header if not already set
	if r.Header.Get("Accept") == "" {
		r.Header.Set("Accept", "application/json")
	}

	// Set Content-Type if not already set (Anthropic requires JSON)
	if r.Header.Get("Content-Type") == "" {
		r.Header.Set("Content-Type", "application/json")
	}

	// Set User-Agent if not already set
	if r.Header.Get("User-Agent") == "" {
		r.Header.Set("User-Agent", "warden-anthropic-proxy")
	}
}
