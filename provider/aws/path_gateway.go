package aws

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/go-chi/chi/middleware"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/aws/processor"
)

var (
	authRegex = regexp.MustCompile(`AWS4-HMAC-SHA256 Credential=([^/]+)/([^/]+)/([^/]+)/([^/]+)/aws4_request`)
	signRegex = regexp.MustCompile(`Signature=([a-f0-9]+)`)
)

// Hop-by-hop headers that should not be included in signatures
// These are defined in RFC 2616 Section 13.5.1 and should be removed before re-signing
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te", // canonicalized version of "TE"
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

// Additional headers that shouldn't be forwarded or signed
var proxyHeaders = []string{
	"X-Forwarded-For",
	"X-Forwarded-Host",
	"X-Forwarded-Proto",
	"X-Forwarded-Port",
	"X-Real-Ip",
	"Forwarded",
}

type contextKey string

const (
	ClientTokenKey contextKey = "clientToken"
	AWSCredsKey    contextKey = "awsCreds"
	TokenKey       contextKey = "token"
	RoleNameKey    contextKey = "roleName"
	PrincipalIDKey contextKey = "principalID"
	TargetURLKey   contextKey = "targetURL"
	ServiceKey     contextKey = "service"
	RegionKey      contextKey = "region"
)

func (b *awsBackend) handleGateway(ctx context.Context, req *logical.Request) {
	// Apply timeout if configured
	if b.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, b.timeout)
		defer cancel()
		req.HTTPRequest = req.HTTPRequest.WithContext(ctx)
	}

	// Set the URL scheme (lost during HTTP parsing)
	if req.HTTPRequest.URL.Scheme == "" {
		if req.HTTPRequest.TLS != nil {
			req.HTTPRequest.URL.Scheme = "https"
		} else {
			req.HTTPRequest.URL.Scheme = "http"
		}
	}

	// Also ensure the URL Host is set (required for signing)
	if req.HTTPRequest.URL.Host == "" {
		req.HTTPRequest.URL.Host = req.HTTPRequest.Host
	}

	// Process the request and prepare it for proxying
	r, err := b.processRequest(ctx, req)
	if err != nil {
		// Error already handled in processRequest
		return
	}

	// Forward the request
	b.proxy.ServeHTTP(req.ResponseWriter, r)
}

// processRequest handles all request processing before proxying
func (b *awsBackend) processRequest(ctx context.Context, req *logical.Request) (*http.Request, error) {
	// Step 1: Read and buffer request body (BEFORE any modifications)
	bodyBytes, err := b.readRequestBody(req.HTTPRequest)
	if err != nil {
		http.Error(req.ResponseWriter, "Failed to read request body", http.StatusBadRequest)
		return nil, err
	}

	// Step 2: Extract service, region, and credentials from Authorization header
	service, region, _, err := extractFromAuthHeader(req.HTTPRequest.Header.Get("Authorization"))
	if err != nil {
		http.Error(req.ResponseWriter, "Unauthorized", http.StatusUnauthorized)
		return nil, err
	}

	// Step 3: Extract authentication data
	creds, err := b.authenticate(req)
	if err != nil {
		http.Error(req.ResponseWriter, "Permission denied", http.StatusForbidden)
		return nil, err
	}

	// Step 4: Verify incoming signature
	valid, err := b.verifyIncomingSignature(req.HTTPRequest, bodyBytes, creds, service, region)
	if err != nil {
		b.logger.Warn("Signature verification failed", logger.Err(err))
		http.Error(req.ResponseWriter, "Signature verification failed", http.StatusForbidden)
		return nil, err
	}
	if !valid {
		b.logger.Warn("Signature does not match")
		http.Error(req.ResponseWriter, "Signature does not match", http.StatusForbidden)
		return nil, fmt.Errorf("signature mismatch")
	}

	// b.logger.Trace("incoming signature verified successfully",
	// 	logger.String("access_key", accessKeyID),
	// 	logger.String("request_id", req.RequestID),
	// )

	// Step 5: Get AWS credentials
	awsCreds, err := b.getCredentials(req)
	if err != nil {
		b.logger.Warn("Fail to extract aws credentials", logger.Err(err))
		http.Error(req.ResponseWriter, "Unauthorized", http.StatusUnauthorized)
		return nil, err
	}

	// Step 6: Create processor context
	processorCtx := &processor.ProcessorContext{
		LogicalRequest: req,
		Service:        service,
		Region:         region,
	}

	// Debug: Log incoming request details for Access Point troubleshooting
	b.logger.Trace("Incoming request details",
		logger.String("method", req.HTTPRequest.Method),
		logger.String("host", req.HTTPRequest.Host),
		logger.String("path", req.HTTPRequest.URL.Path),
		logger.String("rawPath", req.HTTPRequest.URL.RawPath),
		logger.String("escapedPath", req.HTTPRequest.URL.EscapedPath()),
		logger.String("rawQuery", req.HTTPRequest.URL.RawQuery),
		logger.String("service", service),
		logger.String("region", region),
		logger.String("request_id", req.RequestID),
	)

	// Step 7: Find and execute the appropriate processor
	proc := b.processorRegistry.FindProcessor(processorCtx)
	if proc == nil {
		http.Error(req.ResponseWriter, "Service not supported", http.StatusBadRequest)
		return nil, fmt.Errorf("no processor found for service: %s", service)
	}

	b.logger.Trace("Selected processor",
		logger.String("processor", proc.Name()),
		logger.String("request_id", req.RequestID),
	)

	// Step 8: Process the request
	result, err := proc.Process(processorCtx)
	if err != nil {
		http.Error(req.ResponseWriter, "Failed to process request", http.StatusBadGateway)
		return nil, err
	}

	b.logger.Trace("Processor result",
		logger.String("processor", proc.Name()),
		logger.String("targetURL", result.TargetURL),
		logger.String("targetHost", result.TargetHost),
		logger.String("transformedPath", result.TransformedPath),
		logger.Bool("pathIsEncoded", result.TransformedPathIsEncoded),
		logger.String("request_id", req.RequestID),
	)

	// Step 9: Apply the processor result to the request
	target, err := url.Parse(result.TargetURL)
	if err != nil {
		http.Error(req.ResponseWriter, "Internal server error", http.StatusInternalServerError)
		return nil, err
	}

	// Set upstream URL for audit logging
	req.UpstreamURL = result.TargetURL

	req.HTTPRequest.URL.Scheme = target.Scheme
	req.HTTPRequest.URL.Host = target.Host
	req.HTTPRequest.Host = result.TargetHost
	if result.TransformedPath != "" {
		if result.TransformedPathIsEncoded {
			// Path is already URL-encoded, set RawPath to preserve encoding
			// and decode it for Path (Go requires Path to be decoded)
			req.HTTPRequest.URL.RawPath = result.TransformedPath
			// Decode the path for URL.Path
			if decodedPath, err := url.PathUnescape(result.TransformedPath); err == nil {
				req.HTTPRequest.URL.Path = decodedPath
			} else {
				req.HTTPRequest.URL.Path = result.TransformedPath
			}
		} else {
			// Path is not encoded, let Go handle encoding
			req.HTTPRequest.URL.Path = result.TransformedPath
			req.HTTPRequest.URL.RawPath = ""
		}
	}

	// Clear RequestURI - Go's http.Client requires it to be empty for outgoing requests.
	// It will use URL.Path, URL.RawPath, and URL.RawQuery instead.
	req.HTTPRequest.RequestURI = ""

	// Clean up headers before re-signing
	b.cleanHeadersForSigning(req.HTTPRequest)

	// Step 10: Determine signing service (may differ from routing service)
	signingService := result.Service
	if signingService == "s3-control" {
		service = "s3" // S3 Control uses s3 for signing
	}

	// Step 10.5: Determine signing region (may differ from request region)
	// This handles pseudo-regions like "aws-global" that must be converted
	// to real regions (e.g., "us-east-1") for signing.
	signingRegion := region
	if result.SigningRegion != "" {
		signingRegion = result.SigningRegion
	}

	// Step 11: Re-sign the request with valid credentials
	if err := b.resignRequest(ctx, req.HTTPRequest, awsCreds, service, signingRegion, bodyBytes); err != nil {
		http.Error(req.ResponseWriter, "Internal server error", http.StatusInternalServerError)
		return nil, err
	}

	return req.HTTPRequest, nil

}

func (b *awsBackend) authenticate(req *logical.Request) (aws.Credentials, error) {
	return aws.Credentials{
		AccessKeyID:     req.TokenEntry().Data["access_key_id"],
		SecretAccessKey: req.TokenEntry().Data["secret_access_key"],
	}, nil
}

func (b *awsBackend) getCredentials(req *logical.Request) (aws.Credentials, error) {
	switch req.Credential.Type {
	case credential.TypeAWSAccessKeys:
		if req.Credential.LeaseTTL == 0 {
			return aws.Credentials{
				AccessKeyID:     req.Credential.Data["access_key_id"],
				SecretAccessKey: req.Credential.Data["secret_access_key"],
				Source:          req.Credential.Data["cred_source"],
			}, nil
		} else {
			return aws.Credentials{
				AccessKeyID:     req.Credential.Data["access_key_id"],
				SecretAccessKey: req.Credential.Data["secret_access_key"],
				Source:          req.Credential.Data["cred_source"],
				SessionToken:    req.Credential.Data["session_token"],
				CanExpire:       true,
				Expires:         time.Now().Add(req.Credential.LeaseTTL),
			}, nil
		}
	default:
		return aws.Credentials{}, fmt.Errorf("unsupported aws credential type : %s", req.Credential.Type)
	}
}

// extractFromAuthHeader parses service, region, and access key from Authorization header
func extractFromAuthHeader(authHeader string) (service, region, accessKeyID string, err error) {
	if authHeader == "" {
		return "", "", "", fmt.Errorf("empty authorization header")
	}

	matches := authRegex.FindStringSubmatch(authHeader)
	if len(matches) != 5 {
		return "", "", "", fmt.Errorf("invalid authorization header format")
	}

	accessKeyID = matches[1]
	// dateStamp := matches[2] // YYYYMMDD
	region = matches[3]
	service = matches[4]

	return service, region, accessKeyID, nil
}

// computePayloadHash computes SHA256 hash of the payload
func computePayloadHash(body []byte) string {
	h := sha256.New()
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

// parseAWSDate parses AWS date format (YYYYMMDDTHHMMSSZ)
func parseAWSDate(dateStr string) (time.Time, error) {
	return time.Parse("20060102T150405Z", dateStr)
}

func (b *awsBackend) readRequestBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}

	// Limit body size if configured
	reader := io.Reader(r.Body)
	if b.maxBodySize > 0 {
		reader = io.LimitReader(r.Body, b.maxBodySize)
	}

	bodyBytes, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	r.Body.Close()

	// Check if we hit the size limit
	if b.maxBodySize > 0 && int64(len(bodyBytes)) >= b.maxBodySize {
		return nil, fmt.Errorf("request body exceeds maximum size of %d bytes", b.maxBodySize)
	}

	return bodyBytes, nil
}

func (b *awsBackend) restoreRequestBody(r *http.Request, bodyBytes []byte) {
	if len(bodyBytes) > 0 {
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		r.ContentLength = int64(len(bodyBytes))
	} else {
		r.Body = nil
		r.ContentLength = 0
	}
}

func (b *awsBackend) cleanHeadersForSigning(r *http.Request) {
	headers := r.Header
	removedHeaders := []string{}

	// Remove standard hop-by-hop headers
	for _, h := range hopByHopHeaders {
		if headers.Get(h) != "" {
			removedHeaders = append(removedHeaders, h)
			headers.Del(h)
		}
	}

	// Remove proxy-specific headers
	for _, h := range proxyHeaders {
		if headers.Get(h) != "" {
			removedHeaders = append(removedHeaders, h)
			headers.Del(h)
		}
	}

	// Handle Connection header's listed headers
	// If Connection header lists other headers, remove those too
	if connectionHeaders := headers.Get("Connection"); connectionHeaders != "" {
		for _, connHeader := range strings.Split(connectionHeaders, ",") {
			trimmed := strings.TrimSpace(connHeader)
			if trimmed != "" {
				removedHeaders = append(removedHeaders, trimmed)
				headers.Del(trimmed)
			}
		}
	}

	if len(removedHeaders) > 0 {
		b.logger.Trace("headers removed before signing:",
			logger.Any("removed_headers", removedHeaders),
			logger.String("request_id", middleware.GetReqID(r.Context())),
		)
	}
}
