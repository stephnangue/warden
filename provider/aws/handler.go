package aws

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/go-chi/chi/middleware"
	"github.com/stephnangue/warden/audit"
	"github.com/stephnangue/warden/auth/token"
	"github.com/stephnangue/warden/cred"
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
    AWSCredsKey contextKey = "awsCreds"
    TokenKey contextKey = "token"
    RoleNameKey contextKey = "roleName"
    PrincipalIDKey contextKey = "principalID"
    TargetURLKey contextKey = "targetURL"
    ServiceKey contextKey = "service"
    RegionKey contextKey = "region"
)

func (p *AWSProvider) HandleRequest(w http.ResponseWriter, r *http.Request) error{

	p.router.ServeHTTP(w, r)

    return nil
}

func (p *AWSProvider) handleGateway(w http.ResponseWriter, r *http.Request) {

	relativePath := "/v1/" + p.mountPath + "gateway"

	originalPath := r.Context().Value(logical.OriginalPath).(string)

	r.URL.Path = originalPath

	ctx := r.Context()

	// Apply timeout if configured
	if p.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.timeout)
		defer cancel()
		r = r.WithContext(ctx)
	}

	// Set the URL scheme (lost during HTTP parsing)
	if r.URL.Scheme == "" {
		if r.TLS != nil {
			r.URL.Scheme = "https"
		} else {
			r.URL.Scheme = "http"
		}
	}

	// Also ensure the URL Host is set (required for signing)
	if r.URL.Host == "" {
		r.URL.Host = r.Host
	}

	// Process the request and prepare it for proxying
	r, err := p.processRequest(ctx, w, r, relativePath)
	if err != nil {
		// Error already handled in processRequest
		return
	}

	// Forward the request
	p.proxy.ServeHTTP(w, r)
}

// processRequest handles all request processing before proxying
func (p *AWSProvider) processRequest(ctx context.Context, w http.ResponseWriter, r *http.Request, relativePath string) (*http.Request, error) {
	// Step 1: Read and buffer request body (BEFORE any modifications)
	bodyBytes, err := p.readRequestBody(r)
	if err != nil {
		p.auditResponse(nil, r, nil, nil, nil, "", "", http.StatusBadRequest, "Failed to read request body", err.Error(), "", nil)
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return nil, err
	}

	// Step 2: Extract service, region, and credentials from Authorization header
	service, region, accessKeyID, err := extractFromAuthHeader(r.Header.Get("Authorization"))
	if err != nil {
		p.auditResponse(nil, r, nil, nil, nil, "", "", http.StatusUnauthorized, "Unauthorized", err.Error(), "", nil)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return nil, err
	}

	// Step 3: Check the credentials validity and enforce security policies (auth dealine and same origin)
	creds, principalID, roleName, token, err := p.authenticate(r, accessKeyID)
	if err != nil {
		var clientToken *audit.Token
		if token != nil {
			data := make(map[string]string, len(token.Data))
			maps.Copy(data, token.Data)
			clientToken = &audit.Token{
				Type:        token.Type,
				TokenID:     token.ID,
				TokenTTL:    int64(time.Until(token.ExpireAt).Seconds()),
				TokenIssuer: "warden",
				Data:        data,
			}
		}
		p.auditResponse(nil, r, clientToken, nil, nil, roleName, principalID, http.StatusForbidden, "Permission denied", err.Error(), "", nil)
		http.Error(w, "Permission denied", http.StatusForbidden)
		return nil, err
	}

	data := make(map[string]string, len(token.Data))
	maps.Copy(data, token.Data)
	clientToken := &audit.Token{
		Type:        token.Type,
		TokenID:     token.ID,
		TokenTTL:    int64(time.Until(token.ExpireAt).Seconds()),
		TokenIssuer: "warden",
		Data:        data,
	}

	// Step 4: Verify incoming signature
	valid, err := p.verifyIncomingSignature(r, bodyBytes, creds, service, region)
	if err != nil {
		p.auditResponse(nil, r, clientToken, nil, token, roleName, principalID, http.StatusForbidden, "Signature verification failed", err.Error(), "", nil)
		http.Error(w, "Signature verification failed", http.StatusForbidden)
		return nil, err
	}
	if !valid {
		p.auditResponse(nil, r, clientToken, nil, token, roleName, principalID, http.StatusForbidden, "Signature does not match", "signature does not match", "", nil)
		http.Error(w, "Signature does not match", http.StatusForbidden)
		return nil, fmt.Errorf("signature mismatch")
	}

	p.logger.Trace("incoming signature verified successfully",
		logger.String("access_key", accessKeyID),
		logger.String("request_id", middleware.GetReqID(r.Context())),
	)

	// Step 5: Get AWS credentials
	awsCreds, err := p.getCredentials(ctx, accessKeyID, roleName, time.Until(token.ExpireAt))
	if err != nil {
		p.auditResponse(nil, r, clientToken, nil, token, roleName, principalID, http.StatusUnauthorized, "Unauthorized", err.Error(), "", nil)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return nil, err
	}

	// Step 6: Create processor context
	processorCtx := &processor.ProcessorContext{
		Request:      r,
		BodyBytes:    bodyBytes,
		OriginalPath: r.Context().Value(logical.OriginalPath).(string),
		RelativePath: relativePath,
		Credentials:  creds,
		AWSCreds:     awsCreds,
		AccessKeyID:  accessKeyID,
		RoleName:     roleName,
		PrincipalID:  principalID,
		TokenTTL:     time.Until(token.ExpireAt),
		Service:      service,
		Region:       region,
		Ctx:          ctx,
	}

	// Step 7: Find and execute the appropriate processor
	proc := p.processorRegistry.FindProcessor(processorCtx)
	if proc == nil {
		p.auditResponse(nil, r, clientToken, &awsCreds, token, roleName, principalID, http.StatusUnauthorized, "Service not supported", "service not supported", "", 
			map[string]interface{}{
				"service": service,
				"region": region,
			},
		)
		http.Error(w, "Service not supported", http.StatusBadRequest)
		return nil, fmt.Errorf("no processor found for service: %s", service)
	}

	// Step 8: Process the request
	result, err := proc.Process(processorCtx)
	if err != nil {
		p.auditResponse(nil, r, clientToken, &awsCreds, token, roleName, principalID, http.StatusBadGateway, "Failed to process request", err.Error(), "", 
			map[string]interface{}{
				"service": service,
				"region": region,
			},
		)
		http.Error(w, "Failed to process request", http.StatusBadGateway)
		return nil, err
	}

	// Step 9: Apply the processor result to the request
	target, err := url.Parse(result.TargetURL)
	if err != nil {
		p.auditResponse(nil, r, clientToken, &awsCreds, token, roleName, principalID, http.StatusInternalServerError, "Internal server error", err.Error(), "",
			map[string]interface{}{
				"service": service,
				"region": region,
			},
		)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return nil, err
	}

	r.URL.Scheme = target.Scheme
	r.URL.Host = target.Host
	r.Host = result.TargetHost
	if result.TransformedPath != "" {
		r.URL.Path = result.TransformedPath
	}

	r.RequestURI = ""
	
	//Optionally clear RawPath to avoid encoding issues
	if r.URL.Path != "" {
		r.URL.RawPath = ""
	}

	// Clean up headers before re-signing
	p.cleanHeadersForSigning(r)

	// Step 10: Determine signing service (may differ from routing service)
	signingService := result.Service
	if signingService == "s3-control" {
		service = "s3" // S3 Control uses s3 for signing
	}

	// Step 11: Re-sign the request with valid credentials
	if err := p.resignRequest(ctx, r, awsCreds, service, region, bodyBytes); err != nil {
		p.auditResponse(nil, r, clientToken, &awsCreds, token, roleName, principalID, http.StatusInternalServerError, "Internal server error", err.Error(), r.URL.String(),
			map[string]interface{}{
				"service": service,
				"region": region,
			},
		)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return nil, err
	}

	// Store context information for response auditing in ModifyResponse
	ctx = context.WithValue(ctx, ClientTokenKey, clientToken)
	ctx = context.WithValue(ctx, TokenKey, token)
	ctx = context.WithValue(ctx, RoleNameKey, roleName)
	ctx = context.WithValue(ctx, PrincipalIDKey, principalID)
	ctx = context.WithValue(ctx, ServiceKey, service)
	ctx = context.WithValue(ctx, RegionKey, region)
	ctx = context.WithValue(ctx, AWSCredsKey, awsCreds)
	ctx = context.WithValue(ctx, TargetURLKey, result.TargetURL)
	r = r.WithContext(ctx)

	return r, nil

}

func (p *AWSProvider) authenticate(r *http.Request, accessKeyId string) (aws.Credentials, string, string, *token.Token, error) {
	var secretAccessKey, principalId, roleName string
	token := p.tokenAccess.GetToken(accessKeyId)
	if token != nil {
		var clientIP string
		if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			clientIP = ip
		}
		
		// Here we check the credential vadidity, then we enforce the auth deadline policy,
		// finally we enforce the same origin policy
		var err error
		principalId, roleName, err = p.tokenAccess.ResolveToken(r.Context(), accessKeyId, map[string]string{
			"client_ip": clientIP,
		})
		if err != nil {
			p.logger.Warn("aws token resolution failed", 
				logger.Err(err),
				logger.String("request_id", middleware.GetReqID(r.Context())),
			)
			return aws.Credentials{}, "", "", nil, fmt.Errorf("permission denied")
		}

		// Fetch the secretAccessKey from the token store
		secretAccessKey = token.Data["secret_access_key"]
	} else {
		p.logger.Warn("no token found for the provided aws access_key_id", 
			logger.String("access_key_id", accessKeyId),
			logger.String("request_id", middleware.GetReqID(r.Context())),
		)
		return aws.Credentials{}, "", "", nil, fmt.Errorf("permission denied")
	}

	return aws.Credentials{
		AccessKeyID: accessKeyId,
		SecretAccessKey: secretAccessKey,
	}, principalId, roleName, token, nil
}

// getCredentials retrieves AWS credentials for the given access key and role name
func (p *AWSProvider) getCredentials(ctx context.Context, accessKeyID, roleName string, ttl time.Duration) (aws.Credentials, error) {
	credential, err := p.credsProvider.GetCredentials(ctx, accessKeyID, roleName, ttl)
	if err != nil {
		return aws.Credentials{}, err
	}
	switch credential.Type {
	case cred.AWS_ACCESS_KEYS:
		if credential.LeaseTTL == 0 {
			return aws.Credentials{
				AccessKeyID: credential.Data["access_key_id"],
				SecretAccessKey: credential.Data["secret_access_key"],
				Source: credential.Data["cred_source"],
			}, nil
		} else {
			return aws.Credentials{
				AccessKeyID: credential.Data["access_key_id"],
				SecretAccessKey: credential.Data["secret_access_key"],
				Source: credential.Data["cred_source"],
				SessionToken: credential.Data["session_token"],
				CanExpire: true,
				Expires: time.Now().Add(credential.LeaseTTL),
			}, nil
		}
	default:
		return aws.Credentials{}, fmt.Errorf("unsupported aws credential type : %s", credential.Type)
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

func (p *AWSProvider) readRequestBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}

	// Limit body size if configured
	reader := io.Reader(r.Body)
	if p.maxBodySize > 0 {
		reader = io.LimitReader(r.Body, p.maxBodySize)
	}

	bodyBytes, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	r.Body.Close()

	// Check if we hit the size limit
	if p.maxBodySize > 0 && int64(len(bodyBytes)) >= p.maxBodySize {
		return nil, fmt.Errorf("request body exceeds maximum size of %d bytes", p.maxBodySize)
	}

	return bodyBytes, nil
}

func (p *AWSProvider) restoreRequestBody(r *http.Request, bodyBytes []byte) {
	if len(bodyBytes) > 0 {
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		r.ContentLength = int64(len(bodyBytes))
	} else {
		r.Body = nil
		r.ContentLength = 0
	}
}

func (p *AWSProvider) cleanHeadersForSigning(r *http.Request) {
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
		p.logger.Trace("headers removed before signing:",
			logger.Any("removed_headers", removedHeaders),
			logger.String("request_id", middleware.GetReqID(r.Context())),
		)
	}
}