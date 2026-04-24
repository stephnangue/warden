package alicloud

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIsACS3Request(t *testing.T) {
	cases := []struct {
		name string
		auth string
		want bool
	}{
		{"ACS3 prefix", "ACS3-HMAC-SHA256 Credential=x,SignedHeaders=h,Signature=s", true},
		{"AWS SigV4", "AWS4-HMAC-SHA256 Credential=x/...", false},
		{"Bearer token", "Bearer eyJ...", false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			if tc.auth != "" {
				r.Header.Set("Authorization", tc.auth)
			}
			if got := IsACS3Request(r); got != tc.want {
				t.Errorf("IsACS3Request = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseACS3AuthHeader(t *testing.T) {
	auth := "ACS3-HMAC-SHA256 Credential=LTAI123,SignedHeaders=host;x-acs-action;x-acs-date,Signature=deadbeef"
	p, err := parseACS3AuthHeader(auth)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if p.AccessKeyID != "LTAI123" {
		t.Errorf("AccessKeyID = %q, want LTAI123", p.AccessKeyID)
	}
	if len(p.SignedHeaders) != 3 {
		t.Errorf("SignedHeaders len = %d, want 3", len(p.SignedHeaders))
	}
	if p.Signature != "deadbeef" {
		t.Errorf("Signature = %q, want deadbeef", p.Signature)
	}

	// Malformed should return an error
	if _, err := parseACS3AuthHeader("Bearer abc"); err == nil {
		t.Errorf("expected error on non-ACS3 header")
	}
	if _, err := parseACS3AuthHeader("ACS3-HMAC-SHA256 foo=bar"); err == nil {
		t.Errorf("expected error on missing Credential/SignedHeaders/Signature")
	}
}

func TestExtractACS3AccessKeyID(t *testing.T) {
	if got := ExtractACS3AccessKeyID("ACS3-HMAC-SHA256 Credential=my-role,SignedHeaders=host,Signature=s"); got != "my-role" {
		t.Errorf("got %q, want my-role", got)
	}
	if got := ExtractACS3AccessKeyID("Bearer abc"); got != "" {
		t.Errorf("got %q, want empty for non-ACS3", got)
	}
}

func TestSignAndVerifyRoundtrip(t *testing.T) {
	body := []byte(`{"foo":"bar"}`)
	r := httptest.NewRequest("POST", "https://ecs.cn-hangzhou.aliyuncs.com/", strings.NewReader(string(body)))
	r.Header.Set("x-acs-action", "DescribeInstances")
	r.Header.Set("x-acs-version", "2014-05-26")

	if err := SignACS3(r, "LTAI-test-id", "test-secret", "", body); err != nil {
		t.Fatalf("SignACS3 failed: %v", err)
	}

	// Must have all required headers after signing
	for _, h := range []string{
		HeaderAuthorization, HeaderACSDate, HeaderACSContentSHA256,
		HeaderACSSignatureNonce, HeaderHost,
	} {
		if r.Header.Get(h) == "" {
			t.Errorf("missing required header %q after SignACS3", h)
		}
	}

	if !strings.HasPrefix(r.Header.Get(HeaderAuthorization), ACS3Algorithm) {
		t.Errorf("Authorization does not start with %q", ACS3Algorithm)
	}

	// Verification with the same secret should succeed
	valid, err := VerifyACS3(r, "test-secret", body)
	if err != nil {
		t.Fatalf("VerifyACS3 failed: %v", err)
	}
	if !valid {
		t.Errorf("VerifyACS3 = false, want true")
	}

	// Verification with a different secret should fail
	valid, _ = VerifyACS3(r, "wrong-secret", body)
	if valid {
		t.Errorf("VerifyACS3 with wrong secret = true, want false")
	}

	// Tampering with the body should fail verification (body hash won't match x-acs-content-sha256)
	valid, err = VerifyACS3(r, "test-secret", []byte(`{"foo":"tampered"}`))
	if valid || err == nil {
		t.Errorf("VerifyACS3 with tampered body should fail integrity check, got valid=%v err=%v", valid, err)
	}
}

func TestSignWithSecurityToken(t *testing.T) {
	r := httptest.NewRequest("GET", "https://sts.aliyuncs.com/", nil)
	r.Header.Set("x-acs-action", "GetCallerIdentity")
	r.Header.Set("x-acs-version", "2015-04-01")

	if err := SignACS3(r, "LTAI-test-id", "test-secret", "sts-session-token", nil); err != nil {
		t.Fatalf("SignACS3 failed: %v", err)
	}
	if r.Header.Get(HeaderACSSecurityToken) != "sts-session-token" {
		t.Errorf("security token header not set")
	}
	// Security token must be covered by the signature
	if !strings.Contains(r.Header.Get(HeaderAuthorization), "x-acs-security-token") {
		t.Errorf("x-acs-security-token not in SignedHeaders: %s", r.Header.Get(HeaderAuthorization))
	}
	valid, err := VerifyACS3(r, "test-secret", nil)
	if err != nil || !valid {
		t.Errorf("verify failed with security token: valid=%v err=%v", valid, err)
	}
}

func TestCanonicalQueryString(t *testing.T) {
	// Canonical form sorts keys and percent-encodes values.
	got := canonicalQueryString("b=2&a=1&c=hello%20world")
	want := "a=1&b=2&c=hello%20world"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if got := canonicalQueryString(""); got != "" {
		t.Errorf("empty query should produce empty canonical, got %q", got)
	}
}

func TestMissingCredsErrors(t *testing.T) {
	r := httptest.NewRequest("GET", "https://example.com/", nil)
	if err := SignACS3(r, "", "secret", "", nil); err == nil {
		t.Errorf("expected error for missing accessKeyID")
	}
	if err := SignACS3(r, "id", "", "", nil); err == nil {
		t.Errorf("expected error for missing accessKeySecret")
	}
}

// Sanity: VerifyACS3 against a manually constructed request
func TestVerifyRejectsMalformedAuthHeader(t *testing.T) {
	r := httptest.NewRequest("GET", "https://example.com/", nil)
	r.Header.Set("Authorization", "Bearer not-acs3")
	if valid, err := VerifyACS3(r, "secret", nil); err == nil || valid {
		t.Errorf("expected error on malformed auth header, got valid=%v err=%v", valid, err)
	}
}

var _ = http.MethodGet // silence unused import if any
