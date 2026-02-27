package openai

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

// Headers to remove before proxying
var headersToRemove = []string{
	// Security headers (will be replaced with OpenAI API key)
	"Authorization",
	"X-Warden-Token",
	// OpenAI-specific headers (will be injected from credential data)
	"OpenAI-Organization",
	"OpenAI-Project",
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

func (b *openaiBackend) handleGateway(ctx context.Context, req *logical.Request) {
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

	// Get OpenAI credential (API key + optional org/project)
	apiKey, orgID, projectID, err := b.getOpenAICredential(req)
	if err != nil {
		b.Logger.Warn("Failed to get OpenAI API key", logger.Err(err))
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

	// Clean headers and inject OpenAI credentials
	b.prepareHeaders(r, apiKey, orgID, projectID)

	b.Logger.Trace("Proxying OpenAI request",
		logger.String("path", r.URL.Path),
		logger.String("method", r.Method),
		logger.Bool("has_key", apiKey != ""),
	)

	// Forward the request (body streams through without buffering)
	b.Proxy.ServeHTTP(req.ResponseWriter, r)
}

// getOpenAICredential extracts the OpenAI API key and optional org/project from the credential
func (b *openaiBackend) getOpenAICredential(req *logical.Request) (apiKey, orgID, projectID string, err error) {
	if req.Credential == nil {
		return "", "", "", fmt.Errorf("no credential available")
	}

	if req.Credential.Type != credential.TypeAIAPIKey {
		return "", "", "", fmt.Errorf("unsupported credential type: %s", req.Credential.Type)
	}

	apiKey = req.Credential.Data["api_key"]
	if apiKey == "" {
		return "", "", "", fmt.Errorf("credential missing api_key field")
	}

	orgID = req.Credential.Data["organization_id"]
	projectID = req.Credential.Data["project_id"]

	return apiKey, orgID, projectID, nil
}

// buildTargetURL constructs the target OpenAI API URL from the gateway path
func (b *openaiBackend) buildTargetURL(path, rawQuery string) (string, error) {
	// Find gateway path marker
	gatewayIdx := strings.Index(path, "/gateway")
	if gatewayIdx == -1 {
		return "", fmt.Errorf("invalid gateway path: %s", path)
	}

	// Extract path after "/gateway"
	openaiPath := path[gatewayIdx+8:] // len("/gateway") = 8
	if openaiPath == "" || openaiPath == "/" {
		openaiPath = "/"
	}

	if rawQuery != "" {
		return b.openaiURL + openaiPath + "?" + rawQuery, nil
	}
	return b.openaiURL + openaiPath, nil
}

// prepareHeaders removes unwanted headers and injects the OpenAI credentials
func (b *openaiBackend) prepareHeaders(r *http.Request, apiKey, orgID, projectID string) {
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

	// Inject the OpenAI API key using Bearer format
	if apiKey != "" {
		r.Header.Set("Authorization", "Bearer "+apiKey)
	}

	// Inject optional OpenAI organization header
	if orgID != "" {
		r.Header.Set("OpenAI-Organization", orgID)
	}

	// Inject optional OpenAI project header
	if projectID != "" {
		r.Header.Set("OpenAI-Project", projectID)
	}

	// Set Accept header if not already set
	if r.Header.Get("Accept") == "" {
		r.Header.Set("Accept", "application/json")
	}

	// Set User-Agent if not already set
	if r.Header.Get("User-Agent") == "" {
		r.Header.Set("User-Agent", "warden-openai-proxy")
	}
}
