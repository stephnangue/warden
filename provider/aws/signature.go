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

// normalizeRequest prepares a request for re-signing by decoding aws-chunked
// bodies, stripping trailer-related headers, and removing hop-by-hop/proxy
// headers that would break the AWS signature. Returns the (possibly decoded)
// body bytes to forward.
func (b *awsBackend) normalizeRequest(r *http.Request, bodyBytes []byte) []byte {
	// Decode aws-chunked body: the chunk signatures were computed with the
	// client's credentials, which AWS will reject. Decode to plain body and
	// remove streaming-related headers.
	if isAWSChunked(r) {
		decoded, err := decodeAWSChunkedBody(bodyBytes)
		if err != nil {
			b.Logger.Warn("failed to decode aws-chunked body, using original",
				logger.Err(err),
				logger.String("request_id", middleware.GetReqID(r.Context())),
			)
		} else {
			bodyBytes = decoded
		}

		removeAWSChunkedEncoding(r)
		r.Header.Del("X-Amz-Decoded-Content-Length")
		r.Header.Del("X-Amz-Content-Sha256")
		r.Header.Del("Accept-Encoding")
		r.Header.Del("Content-Length")
		r.Header.Del("Expect")
	}

	// Strip trailing-checksum headers when X-Amz-Trailer is present.
	// The SDK sends X-Amz-Trailer to indicate a checksum will follow the body
	// as a trailing chunk. Since we decode aws-chunked, the trailing checksum
	// is lost. Strip the promise headers so AWS doesn't expect a checksum that
	// won't arrive. When X-Amz-Trailer is absent, checksum headers are regular
	// (inline) values that some S3 operations require (e.g., PutObjectLockConfiguration).
	if r.Header.Get("X-Amz-Trailer") != "" {
		r.Header.Del("X-Amz-Trailer")
		r.Header.Del("X-Amz-Sdk-Checksum-Algorithm")
		r.Header.Del("X-Amz-Checksum-Algorithm")
		for key := range r.Header {
			if strings.HasPrefix(strings.ToLower(key), "x-amz-checksum-") {
				r.Header.Del(key)
			}
		}
	}

	// Remove hop-by-hop headers (RFC 2616 Section 13.5.1)
	removedHeaders := []string{}
	for _, h := range []string{
		"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
		"Te", "Trailer", "Trailers", "Transfer-Encoding", "Upgrade",
	} {
		if r.Header.Get(h) != "" {
			removedHeaders = append(removedHeaders, h)
			r.Header.Del(h)
		}
	}

	// Remove proxy-specific headers
	for _, h := range []string{
		"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto",
		"X-Forwarded-Port", "X-Real-Ip", "Forwarded",
	} {
		if r.Header.Get(h) != "" {
			removedHeaders = append(removedHeaders, h)
			r.Header.Del(h)
		}
	}

	// Remove headers listed in Connection header
	if connectionHeaders := r.Header.Get("Connection"); connectionHeaders != "" {
		for _, connHeader := range strings.Split(connectionHeaders, ",") {
			trimmed := strings.TrimSpace(connHeader)
			if trimmed != "" {
				removedHeaders = append(removedHeaders, trimmed)
				r.Header.Del(trimmed)
			}
		}
	}

	if len(removedHeaders) > 0 {
		b.Logger.Trace("headers removed during normalization",
			logger.Any("removed_headers", removedHeaders),
			logger.String("request_id", middleware.GetReqID(r.Context())),
		)
	}

	return bodyBytes
}

// resignRequest re-signs the request with valid AWS credentials.
// The request must already be normalized via normalizeRequest.
func (b *awsBackend) resignRequest(
	ctx context.Context,
	r *http.Request,
	creds aws.Credentials,
	service, region string,
	bodyBytes []byte,
) error {
	// Compute payload hash and set the header. S3 requires
	// X-Amz-Content-Sha256 explicitly; the v4 signer uses the payloadHash
	// for signature computation but does not set the header.
	payloadHash := computePayloadHash(bodyBytes)
	r.Header.Set("X-Amz-Content-Sha256", payloadHash)

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

	// Sign the request with the appropriate signer
	signer := b.getSigner(service)
	if err := signer.SignHTTP(ctx, creds, r, payloadHash, service, region, signingTime); err != nil {
		return fmt.Errorf("failed to sign request: %w", err)
	}

	return nil
}

// isAWSChunked returns true if the request uses aws-chunked content encoding.
func isAWSChunked(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Content-Encoding"), "aws-chunked")
}

// decodeAWSChunkedBody decodes an aws-chunked encoded body into plain bytes.
// AWS chunked format: <hex-size>;chunk-signature=<sig>\r\n<data>\r\n...0;chunk-signature=<sig>\r\n[trailer]\r\n
func decodeAWSChunkedBody(data []byte) ([]byte, error) {
	var decoded bytes.Buffer
	buf := bytes.NewBuffer(data)

	for {
		// Read the chunk header line: "<hex-size>;chunk-signature=<sig>\r\n"
		line, err := buf.ReadString('\n')
		if err != nil {
			if err == io.EOF && line == "" {
				break
			}
			if err == io.EOF {
				// Partial line at end — may be trailing data, stop
				break
			}
			return nil, fmt.Errorf("error reading chunk header: %w", err)
		}

		line = strings.TrimRight(line, "\r\n")

		// Extract hex size (everything before the first ';')
		sizeStr := line
		if idx := strings.IndexByte(line, ';'); idx >= 0 {
			sizeStr = line[:idx]
		}

		var chunkSize int64
		if _, err := fmt.Sscanf(sizeStr, "%x", &chunkSize); err != nil {
			return nil, fmt.Errorf("invalid chunk size %q: %w", sizeStr, err)
		}

		if chunkSize == 0 {
			// Terminal chunk — skip any trailing headers
			break
		}

		// Read chunkSize bytes of data
		chunk := make([]byte, chunkSize)
		if _, err := io.ReadFull(buf, chunk); err != nil {
			return nil, fmt.Errorf("error reading chunk data: %w", err)
		}
		decoded.Write(chunk)

		// Consume trailing \r\n after chunk data
		if _, err := buf.ReadString('\n'); err != nil && err != io.EOF {
			return nil, fmt.Errorf("error reading chunk trailer: %w", err)
		}
	}

	return decoded.Bytes(), nil
}

// removeAWSChunkedEncoding removes "aws-chunked" from the Content-Encoding header
// while preserving any other encodings (e.g., "gzip").
func removeAWSChunkedEncoding(r *http.Request) {
	ce := r.Header.Get("Content-Encoding")
	if ce == "" {
		return
	}
	var remaining []string
	for _, part := range strings.Split(ce, ",") {
		trimmed := strings.TrimSpace(part)
		if !strings.EqualFold(trimmed, "aws-chunked") {
			remaining = append(remaining, trimmed)
		}
	}
	if len(remaining) == 0 {
		r.Header.Del("Content-Encoding")
	} else {
		r.Header.Set("Content-Encoding", strings.Join(remaining, ", "))
	}
}

// getSigner returns the appropriate signer for the service.
// S3 and S3-Control services require DisableURIPathEscaping.
func (b *awsBackend) getSigner(service string) *v4.Signer {
	if service == "s3" || service == "s3-control" {
		return b.s3Signer
	}
	return b.signer
}

// verifyIncomingSignature verifies the AWS Signature V4 of the incoming request.
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

	// Build a new header map containing only the headers the client signed.
	// This ensures the signer produces the same canonical request.
	newHeaders := make(http.Header)
	contentLengthSigned := false
	for _, signedHeader := range signedHeadersList {
		signedHeaderLower := strings.ToLower(strings.TrimSpace(signedHeader))

		if signedHeaderLower == "authorization" {
			continue
		}
		if signedHeaderLower == "content-length" {
			contentLengthSigned = true
		}
		if signedHeaderLower == "host" {
			testReq.Host = r.Host
			testReq.URL.Host = r.Host
			continue
		}

		// Find this header in the original request (case-insensitive)
		for originalHeaderKey, originalHeaderValues := range r.Header {
			if strings.ToLower(originalHeaderKey) == signedHeaderLower {
				canonicalKey := http.CanonicalHeaderKey(signedHeader)
				newHeaders[canonicalKey] = originalHeaderValues
				break
			}
		}

		if newHeaders.Get(http.CanonicalHeaderKey(signedHeader)) == "" && signedHeaderLower != "host" {
			b.Logger.Warn("signed header not found in request",
				logger.String("header", signedHeader),
				logger.String("request_id", middleware.GetReqID(r.Context())),
			)
		}
	}
	testReq.Header = newHeaders

	// Restore body in the cloned request
	if len(bodyBytes) > 0 {
		testReq.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	// Only set ContentLength if the client signed it. The AWS SDK v4 signer
	// automatically includes content-length in canonical headers when
	// ContentLength > 0, causing a mismatch if the client didn't sign it.
	if contentLengthSigned {
		testReq.ContentLength = int64(len(bodyBytes))
	} else {
		testReq.ContentLength = -1
	}

	// Determine payload hash for signature verification. For streaming uploads
	// (aws-chunked), the client uses "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
	// instead of the actual body SHA256. Use the value from the header.
	payloadHash := r.Header.Get("X-Amz-Content-Sha256")
	if payloadHash == "" {
		payloadHash = computePayloadHash(bodyBytes)
	}

	// Sign the test request with the retrieved credentials
	signer := b.getSigner(service)
	err = signer.SignHTTP(r.Context(), creds, testReq, payloadHash, service, region, signingTime)
	if err != nil {
		return false, fmt.Errorf("failed to sign request for signature verification: %w", err)
	}

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
