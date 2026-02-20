package gitlab

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
	// Security headers (will be replaced with real values)
	"Authorization",
	"PRIVATE-TOKEN",
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

func (b *gitlabBackend) handleGateway(ctx context.Context, req *logical.Request) {
	// Check if GitLab address is configured
	if b.gitlabAddress == "" {
		b.Logger.Error("gitlab_address not configured")
		http.Error(req.ResponseWriter, "GitLab provider not configured", http.StatusServiceUnavailable)
		return
	}

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

	// Get GitLab access token from credential
	accessToken, err := b.getAccessToken(req)
	if err != nil {
		b.Logger.Warn("Failed to get GitLab access token", logger.Err(err))
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
	r.Host = r.URL.Host
	r.RequestURI = "" // Required for outgoing requests

	// Clean headers and inject access token
	b.prepareHeaders(r, accessToken)

	// Forward the request (body streams through without buffering)
	b.Proxy.ServeHTTP(req.ResponseWriter, r)
}

// getAccessToken extracts the GitLab access token from the credential
func (b *gitlabBackend) getAccessToken(req *logical.Request) (string, error) {
	if req.Credential == nil {
		return "", fmt.Errorf("no credential available")
	}

	if req.Credential.Type != credential.TypeGitLabAccessToken {
		return "", fmt.Errorf("unsupported credential type: %s", req.Credential.Type)
	}

	token := req.Credential.Data["access_token"]
	if token == "" {
		return "", fmt.Errorf("credential missing access_token field")
	}

	return token, nil
}

// buildTargetURL constructs the target GitLab URL from the gateway path
func (b *gitlabBackend) buildTargetURL(path, rawQuery string) (string, error) {
	// Find gateway path marker
	gatewayIdx := strings.Index(path, "/gateway")
	if gatewayIdx == -1 {
		return "", fmt.Errorf("invalid gateway path: %s", path)
	}

	// Extract path after "/gateway"
	gitlabPath := path[gatewayIdx+8:] // len("/gateway") = 8
	if gitlabPath == "" || gitlabPath == "/" {
		gitlabPath = "/"
	}

	if rawQuery != "" {
		return b.gitlabAddress + gitlabPath + "?" + rawQuery, nil
	}
	return b.gitlabAddress + gitlabPath, nil
}

// prepareHeaders removes unwanted headers and injects the Bearer token
func (b *gitlabBackend) prepareHeaders(r *http.Request, accessToken string) {
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

	// Inject the access token as Bearer (works for both PAT and OAuth2 tokens in GitLab v4 API)
	if accessToken != "" {
		r.Header.Set("Authorization", "Bearer "+accessToken)
	}
}
