// Package alicloud implements ACS3-HMAC-SHA256 request signing and verification
// used by the Alibaba Cloud OpenAPI V3 signature mechanism.
//
// Reference: https://www.alibabacloud.com/help/en/sdk/product-overview/v3-request-structure-and-signature
package alicloud

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	// ACS3Algorithm is the signature algorithm identifier.
	ACS3Algorithm = "ACS3-HMAC-SHA256"

	// HeaderAuthorization is the HTTP authorization header name.
	HeaderAuthorization = "Authorization"
	// HeaderHost is the standard Host header.
	HeaderHost = "Host"
	// HeaderACSDate is the request timestamp header (ISO 8601 UTC).
	HeaderACSDate = "x-acs-date"
	// HeaderACSContentSHA256 is the hex SHA-256 of the request body.
	HeaderACSContentSHA256 = "x-acs-content-sha256"
	// HeaderACSSignatureNonce is a unique nonce per request.
	HeaderACSSignatureNonce = "x-acs-signature-nonce"
	// HeaderACSSecurityToken carries STS security tokens.
	HeaderACSSecurityToken = "x-acs-security-token"
)

// IsACS3Request returns true if the request's Authorization header uses
// the ACS3-HMAC-SHA256 algorithm.
func IsACS3Request(r *http.Request) bool {
	if r == nil {
		return false
	}
	return strings.HasPrefix(r.Header.Get(HeaderAuthorization), ACS3Algorithm)
}

// acs3AuthHeader represents the parsed Authorization header parts.
type acs3AuthHeader struct {
	AccessKeyID   string
	SignedHeaders []string
	Signature     string
}

// parseACS3AuthHeader parses an Authorization header of the form:
//
//	ACS3-HMAC-SHA256 Credential=<id>,SignedHeaders=<h1;h2>,Signature=<hex>
func parseACS3AuthHeader(authHeader string) (*acs3AuthHeader, error) {
	if !strings.HasPrefix(authHeader, ACS3Algorithm) {
		return nil, fmt.Errorf("not an ACS3 authorization header")
	}
	rest := strings.TrimSpace(strings.TrimPrefix(authHeader, ACS3Algorithm))

	out := &acs3AuthHeader{}
	for _, part := range strings.Split(rest, ",") {
		part = strings.TrimSpace(part)
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		val := strings.TrimSpace(kv[1])
		switch key {
		case "Credential":
			out.AccessKeyID = val
		case "SignedHeaders":
			if val != "" {
				out.SignedHeaders = strings.Split(val, ";")
			}
		case "Signature":
			out.Signature = val
		}
	}

	if out.AccessKeyID == "" {
		return nil, fmt.Errorf("missing Credential in authorization header")
	}
	if len(out.SignedHeaders) == 0 {
		return nil, fmt.Errorf("missing SignedHeaders in authorization header")
	}
	if out.Signature == "" {
		return nil, fmt.Errorf("missing Signature in authorization header")
	}
	return out, nil
}

// ExtractACS3AccessKeyID returns the access key ID from an ACS3 authorization header,
// or empty string if the header is malformed or not ACS3.
func ExtractACS3AccessKeyID(authHeader string) string {
	parsed, err := parseACS3AuthHeader(authHeader)
	if err != nil {
		return ""
	}
	return parsed.AccessKeyID
}

// hashSHA256 returns the lowercase hex-encoded SHA-256 of data.
func hashSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// hmacSHA256 computes HMAC-SHA256(key, data).
func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

// generateNonce returns a 32-char hex-encoded random nonce.
func generateNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// canonicalQueryString builds the canonical query string per ACS3 rules:
// parameters sorted by key (then value), keys and values percent-encoded with
// unreserved characters preserved, '=' appended for keys with empty values.
func canonicalQueryString(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return ""
	}

	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var parts []string
	for _, k := range keys {
		vs := values[k]
		sort.Strings(vs)
		for _, v := range vs {
			parts = append(parts, acs3Encode(k)+"="+acs3Encode(v))
		}
	}
	return strings.Join(parts, "&")
}

// acs3Encode percent-encodes s per ACS3 rules: unreserved characters stay as-is,
// spaces become %20 (not +), everything else is %-encoded.
func acs3Encode(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'A' && r <= 'Z') ||
			(r >= 'a' && r <= 'z') ||
			(r >= '0' && r <= '9') ||
			r == '-' || r == '_' || r == '.' || r == '~' {
			b.WriteRune(r)
		} else {
			// Encode as UTF-8 bytes
			for _, by := range []byte(string(r)) {
				b.WriteString(fmt.Sprintf("%%%02X", by))
			}
		}
	}
	return b.String()
}

// canonicalHeaders returns the canonical header block and the SignedHeaders string.
// All headers whose lowercase name is in the signedHeaders slice are included,
// sorted alphabetically, with leading/trailing whitespace trimmed and internal
// whitespace collapsed per ACS3 rules.
func canonicalHeaders(r *http.Request, signedHeaders []string) (canonical string, signed string) {
	// Build a lowercase lookup of header values
	lower := make(map[string]string, len(r.Header)+1)
	for k, vv := range r.Header {
		if len(vv) == 0 {
			continue
		}
		lower[strings.ToLower(k)] = strings.TrimSpace(vv[0])
	}
	// Host is not always in r.Header; use r.Host when present
	if _, ok := lower["host"]; !ok {
		host := r.Host
		if host == "" && r.URL != nil {
			host = r.URL.Host
		}
		if host != "" {
			lower["host"] = host
		}
	}

	// Normalize the signedHeaders input: lowercase, sort, dedupe
	normalized := make([]string, 0, len(signedHeaders))
	seen := make(map[string]struct{}, len(signedHeaders))
	for _, h := range signedHeaders {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		if _, ok := seen[h]; ok {
			continue
		}
		seen[h] = struct{}{}
		normalized = append(normalized, h)
	}
	sort.Strings(normalized)

	var b strings.Builder
	for _, h := range normalized {
		b.WriteString(h)
		b.WriteString(":")
		b.WriteString(lower[h])
		b.WriteString("\n")
	}
	return b.String(), strings.Join(normalized, ";")
}

// defaultSignedHeaders returns the list of headers that ACS3 requires to be
// included in the signature: host, x-acs-*.
func defaultSignedHeaders(r *http.Request) []string {
	out := []string{"host"}
	for k := range r.Header {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-acs-") {
			out = append(out, lk)
		}
	}
	sort.Strings(out)
	return out
}

// SignACS3 computes the ACS3-HMAC-SHA256 signature for r using the given
// credentials and body bytes, then sets the required auth headers on r.
//
// It sets x-acs-date, x-acs-content-sha256, x-acs-signature-nonce, host,
// x-acs-security-token (if token is non-empty), and Authorization.
// Call this before forwarding an outgoing request.
func SignACS3(r *http.Request, accessKeyID, accessKeySecret, securityToken string, body []byte) error {
	if accessKeyID == "" || accessKeySecret == "" {
		return fmt.Errorf("missing access key credentials")
	}

	// Ensure required headers
	if r.Header.Get(HeaderACSDate) == "" {
		r.Header.Set(HeaderACSDate, time.Now().UTC().Format("2006-01-02T15:04:05Z"))
	}
	r.Header.Set(HeaderACSContentSHA256, hashSHA256(body))
	if r.Header.Get(HeaderACSSignatureNonce) == "" {
		nonce, err := generateNonce()
		if err != nil {
			return fmt.Errorf("failed to generate nonce: %w", err)
		}
		r.Header.Set(HeaderACSSignatureNonce, nonce)
	}
	// host must be part of the canonical headers; ensure r.Host is set
	if r.Host == "" && r.URL != nil {
		r.Host = r.URL.Host
	}
	r.Header.Set(HeaderHost, r.Host)
	if securityToken != "" {
		r.Header.Set(HeaderACSSecurityToken, securityToken)
	} else {
		r.Header.Del(HeaderACSSecurityToken)
	}

	signedHeaders := defaultSignedHeaders(r)
	canonicalHdrs, signedHeadersStr := canonicalHeaders(r, signedHeaders)

	canonicalURI := "/"
	if r.URL != nil && r.URL.Path != "" {
		canonicalURI = r.URL.EscapedPath()
	}

	var rawQuery string
	if r.URL != nil {
		rawQuery = r.URL.RawQuery
	}

	canonicalRequest := strings.Join([]string{
		r.Method,
		canonicalURI,
		canonicalQueryString(rawQuery),
		canonicalHdrs,
		signedHeadersStr,
		hashSHA256(body),
	}, "\n")

	stringToSign := ACS3Algorithm + "\n" + hashSHA256([]byte(canonicalRequest))

	sig := hex.EncodeToString(hmacSHA256([]byte(accessKeySecret), stringToSign))

	auth := fmt.Sprintf("%s Credential=%s,SignedHeaders=%s,Signature=%s",
		ACS3Algorithm, accessKeyID, signedHeadersStr, sig)
	r.Header.Set(HeaderAuthorization, auth)
	return nil
}

// VerifyACS3 verifies the ACS3-HMAC-SHA256 signature on an incoming request.
// It parses the existing Authorization header to determine which headers were
// signed, rebuilds the canonical request, and compares signatures in constant
// time.
func VerifyACS3(r *http.Request, accessKeySecret string, body []byte) (bool, error) {
	parsed, err := parseACS3AuthHeader(r.Header.Get(HeaderAuthorization))
	if err != nil {
		return false, err
	}

	canonicalHdrs, signedHeadersStr := canonicalHeaders(r, parsed.SignedHeaders)

	canonicalURI := "/"
	if r.URL != nil && r.URL.Path != "" {
		canonicalURI = r.URL.EscapedPath()
	}

	var rawQuery string
	if r.URL != nil {
		rawQuery = r.URL.RawQuery
	}

	contentHash := r.Header.Get(HeaderACSContentSHA256)
	if contentHash == "" {
		contentHash = hashSHA256(body)
	} else if hashSHA256(body) != contentHash {
		// The client claimed a body hash; the actual body doesn't match.
		// This is an integrity failure — reject without checking the HMAC signature.
		return false, fmt.Errorf("body hash does not match x-acs-content-sha256 header")
	}

	canonicalRequest := strings.Join([]string{
		r.Method,
		canonicalURI,
		canonicalQueryString(rawQuery),
		canonicalHdrs,
		signedHeadersStr,
		contentHash,
	}, "\n")

	stringToSign := ACS3Algorithm + "\n" + hashSHA256([]byte(canonicalRequest))
	expected := hex.EncodeToString(hmacSHA256([]byte(accessKeySecret), stringToSign))

	return subtle.ConstantTimeCompare([]byte(expected), []byte(parsed.Signature)) == 1, nil
}
