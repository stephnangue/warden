package gcp

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

// maxGatewayBodySize is the default max body size if not configured
const maxGatewayBodySize = int64(10 << 20) // 10MB

// Headers to remove before proxying
var headersToRemove = []string{
	// Security headers (will be replaced with GCP Bearer token)
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

// gcpCredentialInfo holds extracted credential information
type gcpCredentialInfo struct {
	bearerToken string
}

func (b *gcpBackend) handleGateway(ctx context.Context, req *logical.Request) {
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
		maxBody = maxGatewayBodySize
	}
	req.HTTPRequest.Body = http.MaxBytesReader(req.ResponseWriter, req.HTTPRequest.Body, maxBody)

	// Parse target GCP host and path from the gateway path
	gcpHost, gcpPath, err := b.parseGatewayPath(req.HTTPRequest.URL.Path)
	if err != nil {
		b.Logger.Warn("Failed to parse gateway path", logger.Err(err))
		http.Error(req.ResponseWriter, err.Error(), http.StatusBadRequest)
		return
	}

	// Get GCP credential info (Bearer token)
	var credInfo gcpCredentialInfo
	if !req.StreamUnauthenticated {
		credInfo, err = b.getGCPCredentialInfo(req)
		if err != nil {
			b.Logger.Warn("Failed to get GCP credentials", logger.Err(err))
			http.Error(req.ResponseWriter, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	// Build target URL
	targetURL := b.buildTargetURL(gcpHost, gcpPath, req.HTTPRequest.URL.RawQuery)

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

	// Clean headers and inject GCP Bearer token (if applicable)
	b.prepareHeaders(r, credInfo.bearerToken)

	b.Logger.Trace("Proxying GCP request",
		logger.String("host", gcpHost),
		logger.String("path", gcpPath),
		logger.String("method", r.Method),
		logger.Bool("has_bearer", credInfo.bearerToken != ""),
	)

	// Forward the request (body streams through without buffering)
	b.Proxy.ServeHTTP(req.ResponseWriter, r)
}

// parseGatewayPath extracts GCP host and path from the gateway path
// Path format: /gcp/gateway/{googleapis-host}/{path...}
// Example: /gcp/gateway/storage.googleapis.com/storage/v1/b/my-bucket
func (b *gcpBackend) parseGatewayPath(path string) (host string, gcpPath string, err error) {
	// Find gateway marker
	gatewayIdx := strings.Index(path, "/gateway/")
	if gatewayIdx == -1 {
		// Check for bare /gateway with no trailing content
		if strings.HasSuffix(path, "/gateway") {
			return "", "", fmt.Errorf("invalid gateway path: no GCP host specified")
		}
		return "", "", fmt.Errorf("invalid gateway path: %s", path)
	}

	// Extract the part after /gateway/
	afterGateway := path[gatewayIdx+9:] // len("/gateway/") = 9
	if afterGateway == "" {
		return "", "", fmt.Errorf("invalid gateway path: no GCP host specified")
	}

	// Split into host and path
	slashIdx := strings.Index(afterGateway, "/")
	if slashIdx == -1 {
		// Just the host, no path
		return afterGateway, "/", nil
	}

	host = afterGateway[:slashIdx]
	gcpPath = afterGateway[slashIdx:]
	if gcpPath == "" {
		gcpPath = "/"
	}

	return host, gcpPath, nil
}

// getGCPCredentialInfo extracts GCP credential info from the request credential
func (b *gcpBackend) getGCPCredentialInfo(req *logical.Request) (gcpCredentialInfo, error) {
	if req.Credential == nil {
		return gcpCredentialInfo{}, fmt.Errorf("no credential available")
	}

	if req.Credential.Type != credential.TypeGCPAccessToken {
		return gcpCredentialInfo{}, fmt.Errorf("unsupported credential type for GCP: %s", req.Credential.Type)
	}

	token := req.Credential.Data["access_token"]
	if token == "" {
		return gcpCredentialInfo{}, fmt.Errorf("credential missing access_token field")
	}
	return gcpCredentialInfo{
		bearerToken: token,
	}, nil
}

// buildTargetURL constructs the full GCP target URL
func (b *gcpBackend) buildTargetURL(host, path, rawQuery string) string {
	var sb strings.Builder
	sb.WriteString("https://")
	sb.WriteString(host)
	sb.WriteString(path)

	if rawQuery != "" {
		sb.WriteString("?")
		sb.WriteString(rawQuery)
	}

	return sb.String()
}

// prepareHeaders removes unwanted headers and injects the GCP Bearer token
func (b *gcpBackend) prepareHeaders(r *http.Request, bearerToken string) {
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

	// Inject the GCP Bearer token
	if bearerToken != "" {
		r.Header.Set("Authorization", "Bearer "+bearerToken)
	}
}
