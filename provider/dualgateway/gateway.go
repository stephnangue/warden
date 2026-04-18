package dualgateway

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/sigv4"
)

// requestSnapshot holds a snapshot of mutable backend state for a single request.
type requestSnapshot struct {
	providerURL string
	maxBodySize int64
	timeout     context.Context
	cancel      context.CancelFunc
	extraState  map[string]any
}

// snapshotState captures mutable fields under read lock for safe concurrent use.
func (b *dualgatewayBackend) snapshotState() requestSnapshot {
	b.mu.RLock()
	defer b.mu.RUnlock()

	// Shallow copy extraState to avoid concurrent map read during config write
	var stateCopy map[string]any
	if b.extraState != nil {
		stateCopy = make(map[string]any, len(b.extraState))
		for k, v := range b.extraState {
			stateCopy[k] = v
		}
	}

	return requestSnapshot{
		providerURL: b.providerURL,
		maxBodySize: b.MaxBodySize,
		extraState:  stateCopy,
	}
}

// extractAPIPath strips the Warden gateway prefix from the request URL path,
// returning only the upstream API path (e.g., "/me", "/instance/v1/zones/fr-par-1/servers").
func extractAPIPath(fullPath string) string {
	idx := strings.Index(fullPath, "/gateway")
	if idx == -1 {
		return fullPath
	}
	apiPath := fullPath[idx+len("/gateway"):]
	if apiPath == "" {
		return "/"
	}
	return apiPath
}

// handleGateway auto-detects the request type and delegates accordingly.
func (b *dualgatewayBackend) handleGateway(ctx context.Context, req *logical.Request) {
	if sigv4.IsSigV4Request(req.HTTPRequest) {
		b.handleS3Request(ctx, req)
	} else {
		b.handleAPIRequest(ctx, req)
	}
}

// handleAPIRequest proxies standard API requests with credential injection.
func (b *dualgatewayBackend) handleAPIRequest(ctx context.Context, req *logical.Request) {
	snap := b.snapshotState()

	// Read body before applying timeout — timeout covers forwarding, not body read
	bodyBytes, err := sigv4.ReadRequestBody(req.HTTPRequest, snap.maxBodySize)
	if err != nil {
		http.Error(req.ResponseWriter, "Failed to read request body", http.StatusBadRequest)
		return
	}

	credValue, err := b.extractAPICredential(req)
	if err != nil {
		b.Logger.Warn("Failed to extract API credentials", logger.Err(err))
		http.Error(req.ResponseWriter, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Apply timeout for forwarding
	if b.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, b.Timeout)
		defer cancel()
	}

	// Build target URL — strip the Warden gateway prefix.
	// Providers that route to multiple upstream hosts based on the request path
	// can supply a RewriteAPITarget hook; otherwise we concatenate providerURL + apiPath.
	apiPath := extractAPIPath(req.HTTPRequest.URL.Path)
	var targetURL string
	if b.spec.RewriteAPITarget != nil {
		var rewriteErr error
		targetURL, rewriteErr = b.spec.RewriteAPITarget(snap.providerURL, apiPath, snap.extraState)
		if rewriteErr != nil {
			b.Logger.Warn("RewriteAPITarget rejected request",
				logger.String("path", apiPath),
				logger.Err(rewriteErr),
			)
			http.Error(req.ResponseWriter, rewriteErr.Error(), http.StatusBadRequest)
			return
		}
	} else {
		targetURL = strings.TrimRight(snap.providerURL, "/") + apiPath
	}

	outReq, err := http.NewRequestWithContext(ctx, req.HTTPRequest.Method, targetURL, nil)
	if err != nil {
		b.Logger.Error("failed to create outgoing request", logger.Err(err))
		http.Error(req.ResponseWriter, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Copy headers, strip Warden/proxy headers
	for k, vv := range req.HTTPRequest.Header {
		for _, v := range vv {
			outReq.Header.Add(k, v)
		}
	}

	headersToRemove := []string{
		"X-Warden-Token", "X-Warden-Role",
		"Connection", "Keep-Alive", "Transfer-Encoding", "Upgrade",
		"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto",
		"X-Forwarded-Port", "X-Real-Ip", "Forwarded",
		"Proxy-Authenticate", "Proxy-Authorization",
	}
	if b.spec.APIAuth.StripAuthorization {
		headersToRemove = append(headersToRemove, "Authorization")
	}
	for _, h := range headersToRemove {
		outReq.Header.Del(h)
	}

	// Inject provider auth
	headerValue := fmt.Sprintf(b.spec.APIAuth.HeaderValueFormat, credValue)
	outReq.Header.Set(b.spec.APIAuth.HeaderName, headerValue)
	outReq.Header.Set("User-Agent", b.spec.UserAgent)

	// Set body
	if len(bodyBytes) > 0 {
		outReq.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		outReq.ContentLength = int64(len(bodyBytes))
	}

	// Copy query string
	outReq.URL.RawQuery = req.HTTPRequest.URL.RawQuery

	b.Logger.Trace("API request details",
		logger.String("method", req.HTTPRequest.Method),
		logger.String("targetURL", targetURL),
		logger.String("path", apiPath),
		logger.String("request_id", req.RequestID),
	)

	// Forward
	transport := b.Proxy.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}

	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		b.Logger.Error("API forward failed", logger.Err(err))
		http.Error(req.ResponseWriter, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			req.ResponseWriter.Header().Add(k, v)
		}
	}
	req.ResponseWriter.WriteHeader(resp.StatusCode)

	if flusher, ok := req.ResponseWriter.(http.Flusher); ok {
		buf := make([]byte, 32*1024)
		for {
			n, readErr := resp.Body.Read(buf)
			if n > 0 {
				req.ResponseWriter.Write(buf[:n])
				flusher.Flush()
			}
			if readErr != nil {
				break
			}
		}
	} else {
		io.Copy(req.ResponseWriter, resp.Body)
	}
}

// handleS3Request proxies S3-compatible requests with SigV4 verification and re-signing.
func (b *dualgatewayBackend) handleS3Request(ctx context.Context, req *logical.Request) {
	snap := b.snapshotState()

	// Set URL scheme and host
	if req.HTTPRequest.URL.Scheme == "" {
		if req.HTTPRequest.TLS != nil {
			req.HTTPRequest.URL.Scheme = "https"
		} else {
			req.HTTPRequest.URL.Scheme = "http"
		}
	}
	if req.HTTPRequest.URL.Host == "" {
		req.HTTPRequest.URL.Host = req.HTTPRequest.Host
	}

	// Step 1: Read and buffer request body (before timeout)
	bodyBytes, err := sigv4.ReadRequestBody(req.HTTPRequest, snap.maxBodySize)
	if err != nil {
		http.Error(req.ResponseWriter, "Failed to read request body", http.StatusBadRequest)
		return
	}
	if bodyBytes == nil {
		bodyBytes = []byte{}
	}

	// Apply timeout for verification + forwarding
	if b.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, b.Timeout)
		defer cancel()
		req.HTTPRequest = req.HTTPRequest.WithContext(ctx)
	}

	// Step 2: Extract service, region, and access key from Authorization header
	service, region, _, err := sigv4.ExtractFromAuthHeader(req.HTTPRequest.Header.Get("Authorization"))
	if err != nil {
		http.Error(req.ResponseWriter, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Step 3: Reconstruct client credentials for signature verification
	accessKeyID := sigv4.ExtractAccessKeyID(req.HTTPRequest.Header.Get("Authorization"))
	verifyCreds := awssdk.Credentials{
		AccessKeyID:     accessKeyID,
		SecretAccessKey: accessKeyID, // JWT or cert: client uses same value for both
	}

	// Step 4: Verify incoming signature
	s3SignerOpts := []func(*v4.SignerOptions){
		func(o *v4.SignerOptions) { o.DisableURIPathEscaping = true },
	}
	valid, err := sigv4.VerifyIncomingSignature(b.Logger, s3SignerOpts, req.HTTPRequest, bodyBytes, verifyCreds, service, region)
	if err != nil {
		b.Logger.Warn("Signature verification failed", logger.Err(err))
		http.Error(req.ResponseWriter, "Signature verification failed", http.StatusForbidden)
		return
	}
	if !valid {
		b.Logger.Warn("Signature does not match")
		http.Error(req.ResponseWriter, "Signature does not match", http.StatusForbidden)
		return
	}

	// Step 5: Get real provider S3 credentials
	realCreds, err := b.extractS3Credentials(req)
	if err != nil {
		b.Logger.Warn("Failed to extract S3 credentials", logger.Err(err))
		http.Error(req.ResponseWriter, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Step 6: Build target URL for provider S3
	apiPath := extractAPIPath(req.HTTPRequest.URL.Path)
	targetHost := b.spec.S3Endpoint(snap.extraState, region)
	if targetHost == "" {
		b.Logger.Error("S3Endpoint returned empty host", logger.String("region", region))
		http.Error(req.ResponseWriter, "Internal server error", http.StatusInternalServerError)
		return
	}
	req.HTTPRequest.URL.Scheme = "https"
	req.HTTPRequest.URL.Host = targetHost
	req.HTTPRequest.URL.Path = apiPath
	req.HTTPRequest.URL.RawPath = ""
	req.HTTPRequest.Host = targetHost
	req.HTTPRequest.RequestURI = ""

	b.Logger.Trace("S3 request details",
		logger.String("method", req.HTTPRequest.Method),
		logger.String("targetHost", targetHost),
		logger.String("path", req.HTTPRequest.URL.Path),
		logger.String("service", service),
		logger.String("region", region),
		logger.String("request_id", req.RequestID),
	)

	// Step 7: Normalize request
	bodyBytes = sigv4.NormalizeRequest(b.Logger, req.HTTPRequest, bodyBytes)

	// Step 8: Re-sign with real provider credentials
	if err := sigv4.ResignRequest(ctx, b.s3Signer, req.HTTPRequest, realCreds, "s3", region, bodyBytes); err != nil {
		b.Logger.Error("Failed to re-sign request", logger.Err(err))
		http.Error(req.ResponseWriter, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Step 9: Forward directly
	transport := b.Proxy.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	sigv4.ForwardDirect(b.Logger, req.ResponseWriter, req.HTTPRequest, bodyBytes, transport)
}
