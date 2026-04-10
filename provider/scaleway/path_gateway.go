package scaleway

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/sigv4"
)

// extractAPIPath strips the Warden gateway prefix from the request URL path,
// returning only the upstream API path (e.g., "/instance/v1/zones/fr-par-1/servers").
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
func (b *scalewayBackend) handleGateway(ctx context.Context, req *logical.Request) {
	if b.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, b.Timeout)
		defer cancel()
		req.HTTPRequest = req.HTTPRequest.WithContext(ctx)
	}

	if sigv4.IsSigV4Request(req.HTTPRequest) {
		b.handleS3Request(ctx, req)
	} else {
		b.handleAPIRequest(ctx, req)
	}
}

// handleAPIRequest proxies standard Scaleway API requests with X-Auth-Token injection.
func (b *scalewayBackend) handleAPIRequest(ctx context.Context, req *logical.Request) {
	bodyBytes, err := sigv4.ReadRequestBody(req.HTTPRequest, b.MaxBodySize)
	if err != nil {
		http.Error(req.ResponseWriter, "Failed to read request body", http.StatusBadRequest)
		return
	}

	secretKey, err := b.getSecretKey(req)
	if err != nil {
		b.Logger.Warn("Failed to extract Scaleway credentials", logger.Err(err))
		http.Error(req.ResponseWriter, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Build target URL — strip the Warden gateway prefix
	apiPath := extractAPIPath(req.HTTPRequest.URL.Path)
	targetURL := strings.TrimRight(b.scalewayURL, "/") + apiPath

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
	for _, h := range []string{
		"X-Warden-Token", "X-Warden-Role",
		"Connection", "Keep-Alive", "Transfer-Encoding", "Upgrade",
		"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto",
		"X-Forwarded-Port", "X-Real-Ip", "Forwarded",
		"Proxy-Authenticate", "Proxy-Authorization",
	} {
		outReq.Header.Del(h)
	}

	// Inject Scaleway auth
	outReq.Header.Set("X-Auth-Token", secretKey)
	outReq.Header.Set("User-Agent", "warden-scaleway-proxy")

	// Set body
	if len(bodyBytes) > 0 {
		outReq.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		outReq.ContentLength = int64(len(bodyBytes))
	}

	// Copy query string
	outReq.URL.RawQuery = req.HTTPRequest.URL.RawQuery

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
func (b *scalewayBackend) handleS3Request(ctx context.Context, req *logical.Request) {
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

	// Step 1: Read and buffer request body
	bodyBytes, err := sigv4.ReadRequestBody(req.HTTPRequest, b.MaxBodySize)
	if err != nil {
		http.Error(req.ResponseWriter, "Failed to read request body", http.StatusBadRequest)
		return
	}
	if bodyBytes == nil {
		bodyBytes = []byte{}
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

	// Step 5: Get real Scaleway credentials
	scaleCreds, err := b.getS3Credentials(req)
	if err != nil {
		b.Logger.Warn("Failed to extract Scaleway S3 credentials", logger.Err(err))
		http.Error(req.ResponseWriter, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Step 6: Build target URL for Scaleway S3
	// Strip the Warden gateway prefix and set the S3 endpoint
	apiPath := extractAPIPath(req.HTTPRequest.URL.Path)
	targetHost := fmt.Sprintf("s3.%s.scw.cloud", region)
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

	// Step 8: Re-sign with real Scaleway credentials
	if err := sigv4.ResignRequest(ctx, b.s3Signer, req.HTTPRequest, scaleCreds, "s3", region, bodyBytes); err != nil {
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

// getSecretKey extracts the Scaleway secret key from the credential.
func (b *scalewayBackend) getSecretKey(req *logical.Request) (string, error) {
	if req.Credential == nil {
		return "", fmt.Errorf("no credential available")
	}
	switch req.Credential.Type {
	case credential.TypeScalewayKeys:
		secretKey := req.Credential.Data["secret_key"]
		if secretKey == "" {
			return "", fmt.Errorf("credential missing secret_key")
		}
		return secretKey, nil
	default:
		return "", fmt.Errorf("unsupported credential type: %s", req.Credential.Type)
	}
}

// getS3Credentials extracts Scaleway access_key and secret_key for SigV4 signing.
func (b *scalewayBackend) getS3Credentials(req *logical.Request) (awssdk.Credentials, error) {
	if req.Credential == nil {
		return awssdk.Credentials{}, fmt.Errorf("no credential available")
	}
	switch req.Credential.Type {
	case credential.TypeScalewayKeys:
		accessKey := req.Credential.Data["access_key"]
		secretKey := req.Credential.Data["secret_key"]
		if accessKey == "" || secretKey == "" {
			return awssdk.Credentials{}, fmt.Errorf("credential missing access_key or secret_key")
		}
		return awssdk.Credentials{
			AccessKeyID:     accessKey,
			SecretAccessKey: secretKey,
		}, nil
	default:
		return awssdk.Credentials{}, fmt.Errorf("unsupported credential type: %s", req.Credential.Type)
	}
}
