package drivers

// Minimal ACS3-HMAC-SHA256 signing helper used by AlicloudDriver to call
// Alicloud management APIs (STS AssumeRole, RAM CreateAccessKey, etc).
//
// This is a subset of what provider/alicloud/signature.go implements: we only
// need outbound signing (no verification), and we always use the same small
// set of signed headers (host, x-acs-*). Keeping it self-contained avoids a
// credential/drivers -> provider/alicloud import.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const acs3Algorithm = "ACS3-HMAC-SHA256"

// signACS3 signs r with the given Alicloud credentials using ACS3-HMAC-SHA256.
// It sets host, x-acs-date, x-acs-content-sha256, x-acs-signature-nonce, and
// Authorization headers. If securityToken != "", x-acs-security-token is also
// set and included in the signature.
func signACS3(r *http.Request, accessKeyID, accessKeySecret, securityToken string, body []byte) error {
	if accessKeyID == "" || accessKeySecret == "" {
		return fmt.Errorf("missing access key credentials")
	}

	// Required headers
	if r.Header.Get("x-acs-date") == "" {
		r.Header.Set("x-acs-date", time.Now().UTC().Format("2006-01-02T15:04:05Z"))
	}
	bodyHash := acs3SHA256(body)
	r.Header.Set("x-acs-content-sha256", bodyHash)
	if r.Header.Get("x-acs-signature-nonce") == "" {
		nonce, err := acs3Nonce()
		if err != nil {
			return fmt.Errorf("nonce: %w", err)
		}
		r.Header.Set("x-acs-signature-nonce", nonce)
	}
	if r.Host == "" && r.URL != nil {
		r.Host = r.URL.Host
	}
	r.Header.Set("Host", r.Host)
	if securityToken != "" {
		r.Header.Set("x-acs-security-token", securityToken)
	}

	// Canonical request
	signedHeaders := acs3SignedHeaders(r)
	canonicalHdrs, signedHeadersStr := acs3CanonicalHeaders(r, signedHeaders)

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
		acs3CanonicalQuery(rawQuery),
		canonicalHdrs,
		signedHeadersStr,
		bodyHash,
	}, "\n")

	stringToSign := acs3Algorithm + "\n" + acs3SHA256([]byte(canonicalRequest))
	sig := hex.EncodeToString(acs3HMAC([]byte(accessKeySecret), stringToSign))

	r.Header.Set("Authorization", fmt.Sprintf("%s Credential=%s,SignedHeaders=%s,Signature=%s",
		acs3Algorithm, accessKeyID, signedHeadersStr, sig))
	return nil
}

func acs3SHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func acs3HMAC(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

func acs3Nonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func acs3SignedHeaders(r *http.Request) []string {
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

func acs3CanonicalHeaders(r *http.Request, signed []string) (canonical, signedStr string) {
	lower := make(map[string]string, len(r.Header)+1)
	for k, vv := range r.Header {
		if len(vv) == 0 {
			continue
		}
		lower[strings.ToLower(k)] = strings.TrimSpace(vv[0])
	}
	if _, ok := lower["host"]; !ok {
		h := r.Host
		if h == "" && r.URL != nil {
			h = r.URL.Host
		}
		if h != "" {
			lower["host"] = h
		}
	}

	seen := make(map[string]struct{}, len(signed))
	normalized := make([]string, 0, len(signed))
	for _, h := range signed {
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

func acs3CanonicalQuery(rawQuery string) string {
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
	// ACS3 v3 sorts query params by name only; values for the same name keep
	// request order. url.Values.Encode() emits '+' for spaces on the wire, but
	// the signed canonical form uses '%20' via acs3Encode — servers re-derive
	// the canonical form from the decoded query, so both match.
	var parts []string
	for _, k := range keys {
		for _, v := range values[k] {
			parts = append(parts, acs3Encode(k)+"="+acs3Encode(v))
		}
	}
	return strings.Join(parts, "&")
}

func acs3Encode(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'A' && r <= 'Z') ||
			(r >= 'a' && r <= 'z') ||
			(r >= '0' && r <= '9') ||
			r == '-' || r == '_' || r == '.' || r == '~' {
			b.WriteRune(r)
		} else {
			for _, by := range []byte(string(r)) {
				b.WriteString(fmt.Sprintf("%%%02X", by))
			}
		}
	}
	return b.String()
}
