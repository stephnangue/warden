package aws

import (
	"bytes"
	"context"
	"crypto/subtle"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/go-chi/chi/middleware"
	"github.com/stephnangue/warden/logger"
)

// resignRequest re-signs the request with valid AWS credentials
func (b *awsBackend) resignRequest(
	ctx context.Context,
	r *http.Request,
	creds aws.Credentials,
	service,
	region string,
	bodyBytes []byte) error {
	// Compute payload hash
	payloadHash := computePayloadHash(bodyBytes)

	// Get signing time from original request or use current time
	signingTime := time.Now()
	if amzDate := r.Header.Get("X-Amz-Date"); amzDate != "" {
		if t, err := parseAWSDate(amzDate); err == nil {
			signingTime = t
		}
	}

	// Remove old authorization header
	r.Header.Del("Authorization")

	// Restore body for signing
	b.restoreRequestBody(r, bodyBytes)

	// Sign the request
	// Use the appropriate signer based on service (S3/S3-Control need DisableURIPathEscaping)
	signer := b.getSigner(service)
	err := signer.SignHTTP(ctx, creds, r, payloadHash, service, region, signingTime)
	if err != nil {
		return fmt.Errorf("failed to sign request: %w", err)
	}

	// b.Logger.Trace("request re-signed successfully",
	// 	logger.String("request_id", middleware.GetReqID(r.Context())),
	// )
	return nil
}

// getSigner returns the appropriate signer for the service.
// S3 and S3-Control services require DisableURIPathEscaping.
func (b *awsBackend) getSigner(service string) *v4.Signer {
	if service == "s3" || service == "s3-control" {
		return b.s3Signer
	}
	return b.signer
}

// verifyIncomingSignature verifies the AWS Signature V4 of the incoming request
func (b *awsBackend) verifyIncomingSignature(
	r *http.Request,
	bodyBytes []byte,
	creds aws.Credentials,
	service, region string,
) (bool, error) {
	// Extract the provided signature from Authorization header
	authHeader := r.Header.Get("Authorization")
	signMatches := signRegex.FindStringSubmatch(authHeader)
	if len(signMatches) != 2 {
		return false, fmt.Errorf("signature not found in authorization header")
	}
	providedSignature := signMatches[1]

	// Extract the signed headers list from the Authorization header
	signedHeadersMatches := signedHeadersRegex.FindStringSubmatch(authHeader)
	if len(signedHeadersMatches) != 2 {
		return false, fmt.Errorf("signed headers not found in authorization header")
	}
	signedHeadersList := strings.Split(signedHeadersMatches[1], ";")

	// Get the signing time from headers
	amzDate := r.Header.Get("X-Amz-Date")
	if amzDate == "" {
		amzDate = r.Header.Get("Date")
	}
	if amzDate == "" {
		return false, fmt.Errorf("no date header found")
	}

	// Parse the signing time
	signingTime, err := parseAWSDate(amzDate)
	if err != nil {
		return false, fmt.Errorf("invalid date format: %w", err)
	}

	// Check if signature is not too old (prevent replay attacks)
	if time.Since(signingTime) > 15*time.Minute {
		return false, fmt.Errorf("signature expired: signed at %s", signingTime.Format(time.RFC3339))
	}

	// Clone the request for verification
	testReq := r.Clone(r.Context())

	b.Logger.Trace("Signature Verification Debug",
		logger.String("method", testReq.Method),
		logger.String("url", testReq.URL.String()),
		logger.String("host", testReq.Host),
		logger.String("path", testReq.URL.Path),
		logger.String("rawPath", testReq.URL.RawPath),
		logger.String("escapedPath", testReq.URL.EscapedPath()),
		logger.String("rawQuery", testReq.URL.RawQuery),
		logger.String("signingTime", signingTime.Format(time.RFC3339)),
		logger.String("service", service),
		logger.String("region", region),
		logger.Any("signedHeaders", signedHeadersList),
		logger.String("request_id", middleware.GetReqID(r.Context())),
	)

	// Remove ALL headers that were NOT signed by the client
	// This ensures we only include the headers the client signed
	newHeaders := make(http.Header)
	for _, signedHeader := range signedHeadersList {
		signedHeaderLower := strings.ToLower(strings.TrimSpace(signedHeader))

		// Skip authorization header - it should never be signed
		if strings.ToLower(signedHeader) == "authorization" {
			continue
		}

		// Find this header in the original request (case-insensitive search)
		// AWS uses lowercase header names in canonical request, but Go uses Title-Case
		found := false
		for originalHeaderKey, originalHeaderValues := range r.Header {
			if strings.ToLower(originalHeaderKey) == signedHeaderLower {
				// Use the canonical form for the new header map
				canonicalKey := http.CanonicalHeaderKey(signedHeader)
				newHeaders[canonicalKey] = originalHeaderValues
				found = true
				break
			}
		}

		if !found && signedHeader != "host" {
			b.Logger.Warn("signed header not found in request",
				logger.String("header", signedHeader),
				logger.String("request_id", middleware.GetReqID(r.Context())),
			)
		}
	}
	testReq.Header = newHeaders

	// Ensure Host is set correctly if it was in signed headers
	for _, sh := range signedHeadersList {
		if strings.ToLower(sh) == "host" {
			testReq.Host = r.Host
			testReq.URL.Host = r.Host
			break
		}
	}

	// NOW log the headers that will actually be used for signing
	// for k, v := range testReq.Header {
	// 	b.Logger.Debug("Header BEFORE signing",
	// 		logger.String("key", k),
	// 		logger.Any("values", v),
	// 		logger.String("request_id", middleware.GetReqID(r.Context())),
	// 	)
	// }

	// b.Logger.Debug("Host/URL BEFORE signing",
	// 	logger.String("r.Host", testReq.Host),
	// 	logger.Any("r.URL", testReq.URL),
	// 	logger.String("request_id", middleware.GetReqID(r.Context())),
	// )

	// Restore body in the cloned request
	if len(bodyBytes) > 0 {
		testReq.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		testReq.ContentLength = int64(len(bodyBytes))
	}

	// Compute payload hash
	payloadHash := computePayloadHash(bodyBytes)

	// clientHash := testReq.Header.Get("X-Amz-Content-Sha256")
	// b.Logger.Debug("Payload hash comparison",
	// 	logger.String("clientHash", clientHash),
	// 	logger.String("ourHash", payloadHash),
	// 	logger.Int("bodyLength", len(bodyBytes)),
	// 	logger.String("request_id", middleware.GetReqID(r.Context())),
	// )

	// Sign the test request with the retrieved credentials
	// Use the appropriate signer based on service (S3/S3-Control need DisableURIPathEscaping)
	signer := b.getSigner(service)
	err = signer.SignHTTP(r.Context(), creds, testReq, payloadHash, service, region, signingTime)
	if err != nil {
		return false, fmt.Errorf("failed to sign request for signature verification: %w", err)
	}

	// DEBUG: Log headers AFTER signing to see what the signer added
	// for k, v := range testReq.Header {
	// 	b.Logger.Debug("Header AFTER signing",
	// 		logger.String("key", k),
	// 		logger.Any("values", v),
	// 		logger.String("request_id", middleware.GetReqID(r.Context())),
	// 	)
	// }

	// b.Logger.Debug("Host/URL AFTER signing",
	// 	logger.String("r.Host", testReq.Host),
	// 	logger.Any("r.URL", testReq.URL),
	// 	logger.String("request_id", middleware.GetReqID(r.Context())),
	// )

	// Extract the calculated signature
	calculatedAuth := testReq.Header.Get("Authorization")
	calculatedMatches := signRegex.FindStringSubmatch(calculatedAuth)
	if len(calculatedMatches) != 2 {
		return false, fmt.Errorf("failed to extract calculated signature")
	}
	calculatedSignature := calculatedMatches[1]

	// Compare signatures using constant-time comparison to prevent timing attacks
	match := subtle.ConstantTimeCompare([]byte(providedSignature), []byte(calculatedSignature)) == 1

	b.Logger.Trace("Signature comparison",
		logger.String("provided", providedSignature),
		logger.String("calculated", calculatedSignature),
		logger.String("originalAuth", authHeader),
		logger.String("calculatedAuth", calculatedAuth),
		logger.String("request_id", middleware.GetReqID(r.Context())),
	)

	if !match {
		b.Logger.Warn("signature mismatch",
			logger.String("provided", providedSignature),
			logger.String("calculated", calculatedSignature),
			logger.String("request_id", middleware.GetReqID(r.Context())),
		)
	}

	return match, nil
}
