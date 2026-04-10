package aws

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/aws/processor"
	"github.com/stephnangue/warden/provider/sigv4"
)

func (b *awsBackend) handleGateway(ctx context.Context, req *logical.Request) {
	// Apply timeout if configured
	if b.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, b.Timeout)
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

	// Ensure the URL Host is set (required for signing)
	if req.HTTPRequest.URL.Host == "" {
		req.HTTPRequest.URL.Host = req.HTTPRequest.Host
	}

	// Process the request: verify signature, normalize, re-sign
	r, body, err := b.processRequest(ctx, req)
	if err != nil {
		return
	}

	// Forward directly via transport, bypassing httputil.ReverseProxy which
	// modifies headers (hop-by-hop cleanup, header reordering) and breaks
	// AWS signatures.
	transport := b.Proxy.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	sigv4.ForwardDirect(b.Logger, req.ResponseWriter, r, body, transport)
}

// processRequest handles all request processing before forwarding.
// Returns the prepared request and body bytes to forward.
func (b *awsBackend) processRequest(ctx context.Context, req *logical.Request) (*http.Request, []byte, error) {
	// Step 1: Read and buffer request body
	bodyBytes, err := sigv4.ReadRequestBody(req.HTTPRequest, b.MaxBodySize)
	if err != nil {
		http.Error(req.ResponseWriter, "Failed to read request body", http.StatusBadRequest)
		return nil, nil, err
	}
	if bodyBytes == nil {
		bodyBytes = []byte{}
	}

	// Step 2: Extract service, region, and credentials from Authorization header
	service, region, _, err := sigv4.ExtractFromAuthHeader(req.HTTPRequest.Header.Get("Authorization"))
	if err != nil {
		http.Error(req.ResponseWriter, "Unauthorized", http.StatusUnauthorized)
		return nil, nil, err
	}

	// Step 3: Reconstruct the credentials the client used for signing.
	// The core already performed JWT/cert auth via performImplicitAuth.
	// We verify the SigV4 signature for request integrity protection.
	accessKeyID := sigv4.ExtractAccessKeyID(req.HTTPRequest.Header.Get("Authorization"))
	securityToken := req.HTTPRequest.Header.Get("X-Amz-Security-Token")

	var verifyCreds awssdk.Credentials
	if strings.HasPrefix(securityToken, "eyJ") {
		// JWT transparent: client used JWT as secret_access_key and session_token
		verifyCreds = awssdk.Credentials{
			AccessKeyID:     accessKeyID,
			SecretAccessKey: securityToken,
			SessionToken:    securityToken,
		}
	} else {
		// Cert transparent: client used role name as both access_key_id and secret_access_key
		verifyCreds = awssdk.Credentials{
			AccessKeyID:     accessKeyID,
			SecretAccessKey: accessKeyID,
		}
	}

	// Step 4: Verify incoming signature
	valid, err := b.verifyIncomingSignature(req.HTTPRequest, bodyBytes, verifyCreds, service, region)
	if err != nil {
		b.Logger.Warn("Signature verification failed", logger.Err(err))
		http.Error(req.ResponseWriter, "Signature verification failed", http.StatusForbidden)
		return nil, nil, err
	}
	if !valid {
		b.Logger.Warn("Signature does not match")
		http.Error(req.ResponseWriter, "Signature does not match", http.StatusForbidden)
		return nil, nil, fmt.Errorf("signature mismatch")
	}

	// Step 5: Clean up security token before re-signing.
	// X-Amz-Security-Token contains the JWT (or is absent for cert auth).
	// Remove it so it doesn't leak into the proxied request.
	// The real AWS session token (if any) will be added by resignRequest when
	// the minted credentials include a SessionToken.
	req.HTTPRequest.Header.Del("X-Amz-Security-Token")

	// Step 6: Get AWS credentials
	awsCreds, err := b.getCredentials(req)
	if err != nil {
		b.Logger.Warn("Fail to extract aws credentials", logger.Err(err))
		http.Error(req.ResponseWriter, "Unauthorized", http.StatusUnauthorized)
		return nil, nil, err
	}

	// Step 7: Create processor context and run processor
	processorCtx := &processor.ProcessorContext{
		LogicalRequest: req,
		Service:        service,
		Region:         region,
	}

	b.Logger.Trace("Incoming request details",
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

	proc := b.processorRegistry.FindProcessor(processorCtx)
	if proc == nil {
		http.Error(req.ResponseWriter, "Service not supported", http.StatusBadRequest)
		return nil, nil, fmt.Errorf("no processor found for service: %s", service)
	}

	b.Logger.Trace("Selected processor",
		logger.String("processor", proc.Name()),
		logger.String("request_id", req.RequestID),
	)

	// Step 8: Process the request
	result, err := proc.Process(processorCtx)
	if err != nil {
		http.Error(req.ResponseWriter, "Failed to process request", http.StatusBadGateway)
		return nil, nil, err
	}

	b.Logger.Trace("Processor result",
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
		return nil, nil, err
	}

	req.HTTPRequest.URL.Scheme = target.Scheme
	req.HTTPRequest.URL.Host = target.Host
	req.HTTPRequest.Host = result.TargetHost
	if result.TransformedPath != "" {
		if result.TransformedPathIsEncoded {
			// Path is already URL-encoded, set RawPath to preserve encoding
			// and decode it for Path (Go requires Path to be decoded)
			req.HTTPRequest.URL.RawPath = result.TransformedPath
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
	req.HTTPRequest.RequestURI = ""

	// Step 10: Determine signing service and region
	signingService := service
	if result.Service != "" {
		signingService = result.Service
	}
	if signingService == "s3-control" {
		signingService = "s3" // S3 Control uses s3 for signing
	}

	signingRegion := region
	if result.SigningRegion != "" {
		signingRegion = result.SigningRegion
	}

	// Step 11: Normalize request (decode aws-chunked, strip hop-by-hop/proxy headers)
	bodyBytes = b.normalizeRequest(req.HTTPRequest, bodyBytes)

	// Step 12: Re-sign the request with valid credentials
	if err := b.resignRequest(ctx, req.HTTPRequest, awsCreds, signingService, signingRegion, bodyBytes); err != nil {
		http.Error(req.ResponseWriter, "Internal server error", http.StatusInternalServerError)
		return nil, nil, err
	}

	return req.HTTPRequest, bodyBytes, nil
}

func (b *awsBackend) getCredentials(req *logical.Request) (awssdk.Credentials, error) {
	switch req.Credential.Type {
	case credential.TypeAWSAccessKeys:
		if req.Credential.LeaseTTL == 0 {
			return awssdk.Credentials{
				AccessKeyID:     req.Credential.Data["access_key_id"],
				SecretAccessKey: req.Credential.Data["secret_access_key"],
				Source:          req.Credential.Data["cred_source"],
			}, nil
		} else {
			return awssdk.Credentials{
				AccessKeyID:     req.Credential.Data["access_key_id"],
				SecretAccessKey: req.Credential.Data["secret_access_key"],
				Source:          req.Credential.Data["cred_source"],
				SessionToken:    req.Credential.Data["session_token"],
				CanExpire:       true,
				Expires:         time.Now().Add(req.Credential.LeaseTTL),
			}, nil
		}
	default:
		return awssdk.Credentials{}, fmt.Errorf("unsupported aws credential type : %s", req.Credential.Type)
	}
}
