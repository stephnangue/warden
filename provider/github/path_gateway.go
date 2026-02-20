package github

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
	// Security headers (will be replaced with GitHub token)
	"Authorization",
	"X-Warden-Token",
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

func (b *githubBackend) handleGateway(ctx context.Context, req *logical.Request) {
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

	// Get GitHub token from credential
	token, err := b.getGitHubToken(req)
	if err != nil {
		b.Logger.Warn("Failed to get GitHub token", logger.Err(err))
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

	// Clean headers and inject GitHub token
	b.prepareHeaders(r, token)

	b.Logger.Trace("Proxying GitHub request",
		logger.String("path", r.URL.Path),
		logger.String("method", r.Method),
		logger.Bool("has_token", token != ""),
	)

	// Forward the request (body streams through without buffering)
	b.Proxy.ServeHTTP(req.ResponseWriter, r)
}

// getGitHubToken extracts the GitHub token from the credential
func (b *githubBackend) getGitHubToken(req *logical.Request) (string, error) {
	if req.Credential == nil {
		return "", fmt.Errorf("no credential available")
	}

	if req.Credential.Type != credential.TypeGitHubToken {
		return "", fmt.Errorf("unsupported credential type: %s", req.Credential.Type)
	}

	token := req.Credential.Data["token"]
	if token == "" {
		return "", fmt.Errorf("credential missing token field")
	}

	return token, nil
}

// buildTargetURL constructs the target GitHub API URL from the gateway path
func (b *githubBackend) buildTargetURL(path, rawQuery string) (string, error) {
	// Find gateway path marker
	gatewayIdx := strings.Index(path, "/gateway")
	if gatewayIdx == -1 {
		return "", fmt.Errorf("invalid gateway path: %s", path)
	}

	// Extract path after "/gateway"
	githubPath := path[gatewayIdx+8:] // len("/gateway") = 8
	if githubPath == "" || githubPath == "/" {
		githubPath = "/"
	}

	if rawQuery != "" {
		return b.githubURL + githubPath + "?" + rawQuery, nil
	}
	return b.githubURL + githubPath, nil
}

// prepareHeaders removes unwanted headers and injects the GitHub token
func (b *githubBackend) prepareHeaders(r *http.Request, token string) {
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

	// Inject the GitHub token using GitHub's preferred format
	if token != "" {
		r.Header.Set("Authorization", "token "+token)
	}

	// Set GitHub API version header if not already set by client
	if r.Header.Get("X-GitHub-Api-Version") == "" {
		r.Header.Set("X-GitHub-Api-Version", b.apiVersion)
	}

	// Set Accept header if not already set
	if r.Header.Get("Accept") == "" {
		r.Header.Set("Accept", "application/vnd.github+json")
	}

	// Set User-Agent if not already set
	if r.Header.Get("User-Agent") == "" {
		r.Header.Set("User-Agent", "warden-github-proxy")
	}
}
