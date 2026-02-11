package vault

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// Headers to remove before proxying
var headersToRemove = []string{
	// Security headers (will be replaced with real values)
	"Authorization",   // Remove Warden auth token to prevent leakage
	"X-Vault-Token",   // Will be replaced with real Vault token
	"X-Vault-Request", // Internal Vault header
	"X-Warden-Token",  // Warden-specific auth header
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

func (b *vaultBackend) handleGateway(ctx context.Context, req *logical.Request) {
	// Check if Vault address is configured
	if b.vaultAddress == "" {
		b.logger.Error("vault_address not configured")
		http.Error(req.ResponseWriter, "Vault provider not configured", http.StatusServiceUnavailable)
		return
	}

	// Apply timeout if configured
	if b.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, b.timeout)
		defer cancel()
		req.HTTPRequest = req.HTTPRequest.WithContext(ctx)
	}

	// Enforce max body size
	maxBody := b.maxBodySize
	if maxBody <= 0 {
		maxBody = DefaultMaxBodySize
	}
	req.HTTPRequest.Body = http.MaxBytesReader(req.ResponseWriter, req.HTTPRequest.Body, maxBody)

	// Get Vault token from credential.
	// For StreamUnauthenticated requests (e.g., PKI /ca/pem, /issuer/+/pem endpoints),
	// vaultToken remains empty and the request is forwarded without authentication.
	// Vault's own ACL handles access control for these public endpoints.
	var vaultToken string
	if !req.StreamUnauthenticated {
		var err error
		vaultToken, err = b.getVaultToken(req)
		if err != nil {
			b.logger.Warn("Failed to get Vault token", logger.Err(err))
			http.Error(req.ResponseWriter, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	// Build target URL
	targetURL, err := b.buildTargetURL(req.HTTPRequest.URL.Path, req.HTTPRequest.URL.RawQuery)
	if err != nil {
		b.logger.Error("Failed to build target URL", logger.Err(err))
		http.Error(req.ResponseWriter, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Prepare request for proxying
	r := req.HTTPRequest
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		b.logger.Error("Failed to parse target URL", logger.Err(err))
		http.Error(req.ResponseWriter, "Internal server error", http.StatusInternalServerError)
		return
	}
	r.URL = parsedURL
	r.Host = r.URL.Host
	r.RequestURI = "" // Required for outgoing requests

	// Clean headers and inject Vault token (if present)
	b.prepareHeaders(r, vaultToken)

	// Set upstream URL for audit logging
	req.UpstreamURL = targetURL

	// Forward the request (body streams through without buffering)
	b.proxy.ServeHTTP(req.ResponseWriter, r)
}

// getVaultToken extracts the Vault token from the credential
func (b *vaultBackend) getVaultToken(req *logical.Request) (string, error) {
	if req.Credential == nil {
		return "", fmt.Errorf("no credential available")
	}

	if req.Credential.Type != credential.TypeVaultToken {
		return "", fmt.Errorf("unsupported credential type: %s", req.Credential.Type)
	}

	token := req.Credential.Data["token"]
	if token == "" {
		return "", fmt.Errorf("credential missing token field")
	}

	return token, nil
}

// buildTargetURL constructs the target Vault URL from the gateway path
func (b *vaultBackend) buildTargetURL(path, rawQuery string) (string, error) {
	// Find gateway path marker
	gatewayIdx := strings.Index(path, "/gateway")
	if gatewayIdx == -1 {
		return "", fmt.Errorf("invalid gateway path: %s", path)
	}

	// Extract path after "/gateway"
	vaultPath := path[gatewayIdx+8:] // len("/gateway") = 8
	if vaultPath == "" || vaultPath == "/" {
		vaultPath = "/v1/"
	} else if !strings.HasPrefix(vaultPath, "/v1/") {
		// Prepend /v1 if not already present
		vaultPath = "/v1" + vaultPath
	}

	// Build URL string directly (avoid url.Parse overhead for simple case)
	if rawQuery != "" {
		return b.vaultAddress + vaultPath + "?" + rawQuery, nil
	}
	return b.vaultAddress + vaultPath, nil
}

// prepareHeaders removes unwanted headers and injects the Vault token (if provided)
func (b *vaultBackend) prepareHeaders(r *http.Request, vaultToken string) {
	// Read Connection header before removing it to handle listed headers
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

	// Inject the real Vault token (if provided)
	// For transparent unauthenticated requests, vaultToken will be empty
	if vaultToken != "" {
		r.Header.Set("X-Vault-Token", vaultToken)
	}
}
