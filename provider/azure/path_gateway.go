package azure

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
	// Security headers (will be replaced with Azure Bearer token)
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

// azureCredentialInfo holds extracted credential information
type azureCredentialInfo struct {
	bearerToken string
}

func (b *azureBackend) handleGateway(ctx context.Context, req *logical.Request) {
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

	// Parse target Azure host and path from the gateway path
	azureHost, azurePath, err := b.parseGatewayPath(req.HTTPRequest.URL.Path)
	if err != nil {
		b.Logger.Warn("Failed to parse gateway path", logger.Err(err))
		http.Error(req.ResponseWriter, err.Error(), http.StatusBadRequest)
		return
	}

	// Get Azure credential info (Bearer token)
	var credInfo azureCredentialInfo
	if !req.StreamUnauthenticated {
		credInfo, err = b.getAzureCredentialInfo(req)
		if err != nil {
			b.Logger.Warn("Failed to get Azure credentials", logger.Err(err))
			http.Error(req.ResponseWriter, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	// Build target URL
	targetURL := b.buildTargetURL(azureHost, azurePath, req.HTTPRequest.URL.RawQuery)

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

	// Clean headers and inject Azure Bearer token (if applicable)
	b.prepareHeaders(r, credInfo.bearerToken)

	b.Logger.Trace("Proxying Azure request",
		logger.String("host", azureHost),
		logger.String("path", azurePath),
		logger.String("method", r.Method),
		logger.Bool("has_bearer", credInfo.bearerToken != ""),
	)

	// Forward the request (body streams through without buffering)
	b.Proxy.ServeHTTP(req.ResponseWriter, r)
}

// parseGatewayPath extracts Azure host and path from the gateway path
// Path format: /azure/gateway/{azure-host}/{path...}
// Example: /azure/gateway/management.azure.com/subscriptions/xxx
func (b *azureBackend) parseGatewayPath(path string) (host string, azurePath string, err error) {
	// Find gateway marker
	gatewayIdx := strings.Index(path, "/gateway/")
	if gatewayIdx == -1 {
		// Check for bare /gateway with no trailing content
		if strings.HasSuffix(path, "/gateway") {
			return "", "", fmt.Errorf("invalid gateway path: no Azure host specified")
		}
		return "", "", fmt.Errorf("invalid gateway path: %s", path)
	}

	// Extract the part after /gateway/
	afterGateway := path[gatewayIdx+9:] // len("/gateway/") = 9
	if afterGateway == "" {
		return "", "", fmt.Errorf("invalid gateway path: no Azure host specified")
	}

	// Split into host and path
	slashIdx := strings.Index(afterGateway, "/")
	if slashIdx == -1 {
		// Just the host, no path
		return afterGateway, "/", nil
	}

	host = afterGateway[:slashIdx]
	azurePath = afterGateway[slashIdx:]
	if azurePath == "" {
		azurePath = "/"
	}

	return host, azurePath, nil
}

// getAzureCredentialInfo extracts Azure credential info from the request credential
func (b *azureBackend) getAzureCredentialInfo(req *logical.Request) (azureCredentialInfo, error) {
	if req.Credential == nil {
		return azureCredentialInfo{}, fmt.Errorf("no credential available")
	}

	if req.Credential.Type != credential.TypeAzureBearerToken {
		return azureCredentialInfo{}, fmt.Errorf("unsupported credential type for Azure: %s", req.Credential.Type)
	}

	token := req.Credential.Data["access_token"]
	if token == "" {
		return azureCredentialInfo{}, fmt.Errorf("credential missing access_token field")
	}
	return azureCredentialInfo{
		bearerToken: token,
	}, nil
}

// buildTargetURL constructs the full Azure target URL
func (b *azureBackend) buildTargetURL(host, path, rawQuery string) string {
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

// prepareHeaders removes unwanted headers and injects the Azure Bearer token
func (b *azureBackend) prepareHeaders(r *http.Request, bearerToken string) {
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

	// Inject the Azure Bearer token
	if bearerToken != "" {
		r.Header.Set("Authorization", "Bearer "+bearerToken)
	}
}

