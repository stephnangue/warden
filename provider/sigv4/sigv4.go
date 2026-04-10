// Package sigv4 provides reusable AWS Signature Version 4 utilities for
// providers that proxy S3-compatible storage APIs (AWS, Scaleway, Cloudflare R2, OVH).
package sigv4

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/go-chi/chi/middleware"
	"github.com/stephnangue/warden/logger"
)


var (
	// AuthRegex parses the SigV4 Authorization header into access_key_id, date, region, service.
	AuthRegex = regexp.MustCompile(`AWS4-HMAC-SHA256 Credential=([^/]+)/([^/]+)/([^/]+)/([^/]+)/aws4_request`)

	// SignRegex extracts the hex signature value.
	SignRegex = regexp.MustCompile(`Signature=([a-f0-9]+)`)

	// SignedHeadersRegex extracts the semicolon-delimited signed headers list.
	SignedHeadersRegex = regexp.MustCompile(`SignedHeaders=([^,]+)`)
)

// IsSigV4Request returns true if the request carries an AWS SigV4 Authorization header.
func IsSigV4Request(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256")
}

// ExtractFromAuthHeader parses service, region, and access key from a SigV4 Authorization header.
func ExtractFromAuthHeader(authHeader string) (service, region, accessKeyID string, err error) {
	if authHeader == "" {
		return "", "", "", fmt.Errorf("empty authorization header")
	}
	matches := AuthRegex.FindStringSubmatch(authHeader)
	if len(matches) != 5 {
		return "", "", "", fmt.Errorf("invalid authorization header format")
	}
	return matches[4], matches[3], matches[1], nil
}

// ExtractAccessKeyID extracts the Access Key ID from a SigV4 Authorization header.
func ExtractAccessKeyID(authHeader string) string {
	const prefix = "Credential="
	idx := strings.Index(authHeader, prefix)
	if idx == -1 {
		return ""
	}
	start := idx + len(prefix)
	if start >= len(authHeader) {
		return ""
	}
	end := strings.IndexByte(authHeader[start:], '/')
	if end == -1 {
		return ""
	}
	return authHeader[start : start+end]
}

// ComputePayloadHash computes the SHA256 hash of the payload.
func ComputePayloadHash(body []byte) string {
	h := sha256.New()
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

// ParseAWSDate parses the AWS date format (YYYYMMDDTHHMMSSZ).
func ParseAWSDate(dateStr string) (time.Time, error) {
	return time.Parse("20060102T150405Z", dateStr)
}

// ReadRequestBody reads and buffers the request body, enforcing maxSize.
func ReadRequestBody(r *http.Request, maxSize int64) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	reader := io.Reader(r.Body)
	if maxSize > 0 {
		reader = io.LimitReader(r.Body, maxSize)
	}
	bodyBytes, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	r.Body.Close()
	if maxSize > 0 && int64(len(bodyBytes)) >= maxSize {
		return nil, fmt.Errorf("request body exceeds maximum size of %d bytes", maxSize)
	}
	return bodyBytes, nil
}

// RestoreRequestBody sets the request body back to the given bytes.
func RestoreRequestBody(r *http.Request, bodyBytes []byte) {
	if len(bodyBytes) > 0 {
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		r.ContentLength = int64(len(bodyBytes))
	} else {
		r.Body = nil
		r.ContentLength = 0
	}
}

// NormalizeRequest prepares a request for re-signing by decoding aws-chunked
// bodies, stripping trailer-related headers, and removing hop-by-hop/proxy
// headers that would break the signature. Returns the (possibly decoded) body bytes.
func NormalizeRequest(log *logger.GatedLogger, r *http.Request, bodyBytes []byte) []byte {
	// Decode aws-chunked body
	if IsAWSChunked(r) {
		decoded, err := DecodeAWSChunkedBody(bodyBytes)
		if err != nil {
			log.Warn("failed to decode aws-chunked body, using original",
				logger.Err(err),
				logger.String("request_id", middleware.GetReqID(r.Context())),
			)
		} else {
			bodyBytes = decoded
		}
		RemoveAWSChunkedEncoding(r)
		r.Header.Del("X-Amz-Decoded-Content-Length")
		r.Header.Del("X-Amz-Content-Sha256")
		r.Header.Del("Accept-Encoding")
		r.Header.Del("Content-Length")
		r.Header.Del("Expect")
	}

	// Strip trailing-checksum headers when X-Amz-Trailer is present.
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
		log.Trace("headers removed during normalization",
			logger.Any("removed_headers", removedHeaders),
			logger.String("request_id", middleware.GetReqID(r.Context())),
		)
	}

	return bodyBytes
}

// ResignRequest re-signs the request with the given credentials.
// The request must already be normalized via NormalizeRequest.
func ResignRequest(
	ctx context.Context,
	signer *v4.Signer,
	r *http.Request,
	creds aws.Credentials,
	service, region string,
	bodyBytes []byte,
) error {
	payloadHash := ComputePayloadHash(bodyBytes)
	r.Header.Set("X-Amz-Content-Sha256", payloadHash)

	signingTime := time.Now()
	if amzDate := r.Header.Get("X-Amz-Date"); amzDate != "" {
		if t, err := ParseAWSDate(amzDate); err == nil {
			signingTime = t
		}
	}

	r.Header.Del("Authorization")
	RestoreRequestBody(r, bodyBytes)

	if err := signer.SignHTTP(ctx, creds, r, payloadHash, service, region, signingTime); err != nil {
		return fmt.Errorf("failed to sign request: %w", err)
	}
	return nil
}

// VerifyIncomingSignature verifies the AWS Signature V4 of the incoming request.
// It accepts signer options rather than a signer instance because the v4.Signer
// caches derived signing keys — reusing a signer across different credentials
// produces incorrect results. A fresh signer is created per verification call.
func VerifyIncomingSignature(
	log *logger.GatedLogger,
	signerOpts []func(*v4.SignerOptions),
	r *http.Request,
	bodyBytes []byte,
	creds aws.Credentials,
	service, region string,
) (bool, error) {
	// Extract the provided signature
	authHeader := r.Header.Get("Authorization")
	signMatches := SignRegex.FindStringSubmatch(authHeader)
	if len(signMatches) != 2 {
		return false, fmt.Errorf("signature not found in authorization header")
	}
	providedSignature := signMatches[1]

	// Extract the signed headers list
	signedHeadersMatches := SignedHeadersRegex.FindStringSubmatch(authHeader)
	if len(signedHeadersMatches) != 2 {
		return false, fmt.Errorf("signed headers not found in authorization header")
	}
	signedHeadersList := strings.Split(signedHeadersMatches[1], ";")

	// Get the signing time
	amzDate := r.Header.Get("X-Amz-Date")
	if amzDate == "" {
		amzDate = r.Header.Get("Date")
	}
	if amzDate == "" {
		return false, fmt.Errorf("no date header found")
	}
	signingTime, err := ParseAWSDate(amzDate)
	if err != nil {
		return false, fmt.Errorf("invalid date format: %w", err)
	}

	// Replay protection
	if time.Since(signingTime) > 15*time.Minute {
		return false, fmt.Errorf("signature expired: signed at %s", signingTime.Format(time.RFC3339))
	}

	// Clone the request for verification
	testReq := r.Clone(r.Context())

	log.Trace("Signature Verification Debug",
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

		for originalHeaderKey, originalHeaderValues := range r.Header {
			if strings.ToLower(originalHeaderKey) == signedHeaderLower {
				canonicalKey := http.CanonicalHeaderKey(signedHeader)
				newHeaders[canonicalKey] = originalHeaderValues
				break
			}
		}

		if newHeaders.Get(signedHeader) == "" && signedHeaderLower != "host" {
			log.Warn("signed header not found in request",
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

	if contentLengthSigned {
		testReq.ContentLength = int64(len(bodyBytes))
	} else {
		testReq.ContentLength = -1
	}

	// Determine payload hash for signature verification
	payloadHash := r.Header.Get("X-Amz-Content-Sha256")
	if payloadHash == "" {
		payloadHash = ComputePayloadHash(bodyBytes)
	}

	// Create a fresh signer to avoid key caching from prior calls with
	// different credentials. v4.NewSigner is cheap (struct allocation only).
	verifySigner := v4.NewSigner(signerOpts...)
	err = verifySigner.SignHTTP(r.Context(), creds, testReq, payloadHash, service, region, signingTime)
	if err != nil {
		return false, fmt.Errorf("failed to sign request for signature verification: %w", err)
	}

	// Extract calculated signature
	calculatedAuth := testReq.Header.Get("Authorization")
	calculatedMatches := SignRegex.FindStringSubmatch(calculatedAuth)
	if len(calculatedMatches) != 2 {
		return false, fmt.Errorf("failed to extract calculated signature")
	}
	calculatedSignature := calculatedMatches[1]

	// Constant-time comparison
	match := subtle.ConstantTimeCompare([]byte(providedSignature), []byte(calculatedSignature)) == 1

	log.Trace("Signature comparison",
		logger.String("provided", providedSignature),
		logger.String("calculated", calculatedSignature),
		logger.String("originalAuth", authHeader),
		logger.String("calculatedAuth", calculatedAuth),
		logger.String("request_id", middleware.GetReqID(r.Context())),
	)

	if !match {
		log.Warn("signature mismatch",
			logger.String("provided", providedSignature),
			logger.String("calculated", calculatedSignature),
			logger.String("request_id", middleware.GetReqID(r.Context())),
		)
	}

	return match, nil
}

// IsAWSChunked returns true if the request uses aws-chunked content encoding.
func IsAWSChunked(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Content-Encoding"), "aws-chunked")
}

// DecodeAWSChunkedBody decodes an aws-chunked encoded body into plain bytes.
func DecodeAWSChunkedBody(data []byte) ([]byte, error) {
	var decoded bytes.Buffer
	buf := bytes.NewBuffer(data)

	for {
		line, err := buf.ReadString('\n')
		if err != nil {
			if err == io.EOF && line == "" {
				break
			}
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("error reading chunk header: %w", err)
		}

		line = strings.TrimRight(line, "\r\n")

		sizeStr := line
		if idx := strings.IndexByte(line, ';'); idx >= 0 {
			sizeStr = line[:idx]
		}

		var chunkSize int64
		if _, err := fmt.Sscanf(sizeStr, "%x", &chunkSize); err != nil {
			return nil, fmt.Errorf("invalid chunk size %q: %w", sizeStr, err)
		}

		if chunkSize == 0 {
			break
		}

		chunk := make([]byte, chunkSize)
		if _, err := io.ReadFull(buf, chunk); err != nil {
			return nil, fmt.Errorf("error reading chunk data: %w", err)
		}
		decoded.Write(chunk)

		if _, err := buf.ReadString('\n'); err != nil && err != io.EOF {
			return nil, fmt.Errorf("error reading chunk trailer: %w", err)
		}
	}

	return decoded.Bytes(), nil
}

// RemoveAWSChunkedEncoding removes "aws-chunked" from the Content-Encoding header.
func RemoveAWSChunkedEncoding(r *http.Request) {
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

// ForwardDirect sends a signed request directly using the given transport,
// bypassing httputil.ReverseProxy which modifies headers and breaks SigV4 signatures.
func ForwardDirect(log *logger.GatedLogger, w http.ResponseWriter, r *http.Request, body []byte, transport http.RoundTripper) {
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), bytes.NewReader(body))
	if err != nil {
		log.Error("failed to create direct request", logger.Err(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	outReq.Header = r.Header.Clone()
	outReq.Host = r.Host
	outReq.ContentLength = int64(len(body))

	if transport == nil {
		transport = http.DefaultTransport
	}

	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		log.Error("direct forward failed", logger.Err(err))
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		for _, val := range vv {
			w.Header().Add(k, val)
		}
	}
	w.WriteHeader(resp.StatusCode)

	if flusher, ok := w.(http.Flusher); ok {
		buf := make([]byte, 32*1024)
		for {
			n, readErr := resp.Body.Read(buf)
			if n > 0 {
				w.Write(buf[:n])
				flusher.Flush()
			}
			if readErr != nil {
				break
			}
		}
	} else {
		io.Copy(w, resp.Body)
	}
}
