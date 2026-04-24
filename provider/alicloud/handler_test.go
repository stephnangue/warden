package alicloud

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// signClientRequest signs an HTTP request using the provided client credentials
// (simulating what a Warden client SDK would do).
func signClientRequest(t *testing.T, method, rawURL, body, clientKeyID, clientSecret, securityToken string) *http.Request {
	t.Helper()
	bodyBytes := []byte(body)
	r := httptest.NewRequest(method, rawURL, strings.NewReader(body))
	r.ContentLength = int64(len(bodyBytes))
	r.Header.Set("x-acs-action", "DescribeInstances")
	r.Header.Set("x-acs-version", "2014-05-26")
	if err := SignACS3(r, clientKeyID, clientSecret, securityToken, bodyBytes); err != nil {
		t.Fatalf("signing client request: %v", err)
	}
	// Restore body since SignACS3 doesn't touch it but httptest consumed it
	r.Body = io.NopCloser(strings.NewReader(body))
	return r
}

// TestHandleGateway_SubdomainRewrite covers the reverse-proxy flow end-to-end:
// the client signs with a "<real>.aliyuncs.com.<proxy-domain>" Host, Warden
// verifies against that host, rewrites to the bare Alicloud target, and
// re-signs. The upstream sees the real Alicloud host in Credential= and Host:.
func TestHandleGateway_SubdomainRewrite(t *testing.T) {
	var receivedHost string
	var receivedAuth string

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHost = r.Host
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	b := setupBackend(t)
	b.Proxy.Transport = upstream.Client().Transport
	// Configure the proxy domain.
	b.mu.Lock()
	b.proxyDomains = []string{"warden.example.com"}
	b.mu.Unlock()

	// Client signs with the full subdomain form — this is what a native
	// Alicloud SDK would do when its endpoint is set to the wildcard host.
	body := `{"x":1}`
	r := signClientRequest(t, "POST",
		"https://ecs.cn-hangzhou.aliyuncs.com.warden.example.com/",
		body, "role-reader", "role-reader", "")

	// Redirect the transport at the test server while keeping r.Host intact
	// so signature verification sees the subdomain form the client signed.
	u, _ := url.Parse(upstream.URL)
	r.URL.Scheme = u.Scheme
	r.URL.Host = u.Host

	rec := httptest.NewRecorder()
	req := &logical.Request{
		HTTPRequest:    r,
		ResponseWriter: rec,
		Credential: &credential.Credential{
			Type: credential.TypeAlicloudKeys,
			Data: map[string]string{
				"access_key_id":     "LTAI-real-id",
				"access_key_secret": "real-secret",
			},
		},
	}
	b.handleGateway(context.Background(), req)
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	// Upstream must see the REAL Alicloud host — the proxy suffix is stripped.
	assert.Equal(t, "ecs.cn-hangzhou.aliyuncs.com", receivedHost,
		"target host should be stripped of proxy_domain suffix")
	assert.Contains(t, receivedAuth, "Credential=LTAI-real-id")
	assert.NotContains(t, receivedAuth, "warden.example.com",
		"re-signed Authorization must not reference the proxy domain")
}

func TestHandleGateway_UnknownHostRejected(t *testing.T) {
	b := setupBackend(t)

	r := signClientRequest(t, "POST", "https://evil.example.com/", "{}", "role-reader", "role-reader", "")

	rec := httptest.NewRecorder()
	req := &logical.Request{
		HTTPRequest:    r,
		ResponseWriter: rec,
		Credential: &credential.Credential{
			Type: credential.TypeAlicloudKeys,
			Data: map[string]string{"access_key_id": "x", "access_key_secret": "y"},
		},
	}
	b.handleGateway(context.Background(), req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "not a recognised Alicloud target")
}

func TestHandleGateway_MetadataHostRejected(t *testing.T) {
	// SSRF guard: the Alicloud ECS metadata service IP must be refused even
	// if the client produces a syntactically valid ACS3 signature over it.
	b := setupBackend(t)

	r := signClientRequest(t, "GET", "http://100.100.100.200/latest/meta-data/",
		"", "role-reader", "role-reader", "")

	rec := httptest.NewRecorder()
	req := &logical.Request{
		HTTPRequest:    r,
		ResponseWriter: rec,
		Credential: &credential.Credential{
			Type: credential.TypeAlicloudKeys,
			Data: map[string]string{"access_key_id": "x", "access_key_secret": "y"},
		},
	}
	b.handleGateway(context.Background(), req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHandleGateway_UnsupportedAuth(t *testing.T) {
	b := setupBackend(t)
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "https://ecs.cn-hangzhou.aliyuncs.com/", nil)
	r.Header.Set("Authorization", "Bearer not-acs3")

	req := &logical.Request{HTTPRequest: r, ResponseWriter: rec}
	b.handleGateway(context.Background(), req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHandleGateway_SignatureMismatch(t *testing.T) {
	b := setupBackend(t)

	// Sign with one secret, but the verify will use a different one
	r := signClientRequest(t, "POST", "https://ecs.cn-hangzhou.aliyuncs.com/", `{"x":1}`, "role-foo", "role-foo", "")
	// Tamper with signature
	auth := r.Header.Get("Authorization")
	r.Header.Set("Authorization", strings.Replace(auth, "Signature=", "Signature=deadbeef", 1))

	rec := httptest.NewRecorder()
	req := &logical.Request{
		HTTPRequest:    r,
		ResponseWriter: rec,
		Credential: &credential.Credential{
			Type: credential.TypeAlicloudKeys,
			Data: map[string]string{"access_key_id": "LTAI-real", "access_key_secret": "real-secret"},
		},
	}
	b.handleGateway(context.Background(), req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestHandleGateway_MissingCredential(t *testing.T) {
	b := setupBackend(t)

	// Cert transparent: role name as both access_key_id and access_key_secret
	r := signClientRequest(t, "POST", "https://ecs.cn-hangzhou.aliyuncs.com/", `{}`, "role-reader", "role-reader", "")

	rec := httptest.NewRecorder()
	req := &logical.Request{HTTPRequest: r, ResponseWriter: rec}
	b.handleGateway(context.Background(), req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestHandleGateway_WrongCredentialType(t *testing.T) {
	b := setupBackend(t)
	r := signClientRequest(t, "POST", "https://ecs.cn-hangzhou.aliyuncs.com/", `{}`, "role-reader", "role-reader", "")

	rec := httptest.NewRecorder()
	req := &logical.Request{
		HTTPRequest:    r,
		ResponseWriter: rec,
		Credential: &credential.Credential{
			Type: credential.TypeAWSAccessKeys, // wrong type
			Data: map[string]string{"access_key_id": "AKIA", "secret_access_key": "x"},
		},
	}
	b.handleGateway(context.Background(), req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// TestHandleGateway_ForwardsSignedRequest exercises the full verify + re-sign +
// forward flow against a test upstream and confirms the upstream sees a valid
// ACS3 signature generated with the real credentials.
func TestHandleGateway_ForwardsSignedRequest(t *testing.T) {
	var receivedAuth string
	var receivedAction string
	var receivedBody string

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		receivedAction = r.Header.Get("x-acs-action")
		bodyBytes, _ := io.ReadAll(r.Body)
		receivedBody = string(bodyBytes)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	b := setupBackend(t)
	// Point transport at upstream's TLS (self-signed)
	b.Proxy.Transport = upstream.Client().Transport

	// Client signs with its role name (cert transparent)
	body := `{"instance":"i-123"}`
	r := signClientRequest(t, "POST", "https://ecs.cn-hangzhou.aliyuncs.com/", body, "role-reader", "role-reader", "")

	// Redirect to the test upstream, preserving the Host header so re-signing
	// computes the right canonical request
	u, _ := url.Parse(upstream.URL)
	r.URL.Scheme = u.Scheme
	r.URL.Host = u.Host
	// Keep r.Host as the Alicloud virtual host so the signature is over ecs.cn-hangzhou.aliyuncs.com

	rec := httptest.NewRecorder()
	req := &logical.Request{
		HTTPRequest:    r,
		ResponseWriter: rec,
		Credential: &credential.Credential{
			Type: credential.TypeAlicloudKeys,
			Data: map[string]string{
				"access_key_id":     "LTAI-real-id",
				"access_key_secret": "real-secret",
			},
		},
	}
	b.handleGateway(context.Background(), req)

	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	// Verify the upstream received a request signed with the REAL credentials,
	// not the client's role name.
	assert.True(t, strings.HasPrefix(receivedAuth, ACS3Algorithm), "upstream should see ACS3 auth: %q", receivedAuth)
	assert.Contains(t, receivedAuth, "Credential=LTAI-real-id", "must be signed with real access_key_id, not role name")
	assert.NotContains(t, receivedAuth, "Credential=role-reader")
	assert.Equal(t, "DescribeInstances", receivedAction, "x-acs-action must be preserved")
	assert.Equal(t, body, receivedBody, "body must be forwarded unchanged")
}

// TestHandleGateway_JWTSecurityToken covers the JWT transparent auth path
// where the client uses a JWT as access_key_secret + x-acs-security-token.
func TestHandleGateway_JWTSecurityToken(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Real forwarded request must NOT leak the JWT
		assert.NotContains(t, r.Header.Get("x-acs-security-token"), "eyJ", "JWT must not be forwarded")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	b := setupBackend(t)
	b.Proxy.Transport = upstream.Client().Transport

	// Client signs using a JWT as both x-acs-security-token and access_key_secret.
	// access_key_id can be anything.
	jwt := "eyJhbGciOiJIUzI1NiJ9.test.sig"
	r := signClientRequest(t, "POST", "https://ecs.cn-hangzhou.aliyuncs.com/", `{}`, "anything", jwt, jwt)

	u, _ := url.Parse(upstream.URL)
	r.URL.Scheme = u.Scheme
	r.URL.Host = u.Host

	rec := httptest.NewRecorder()
	req := &logical.Request{
		HTTPRequest:    r,
		ResponseWriter: rec,
		Credential: &credential.Credential{
			Type: credential.TypeAlicloudKeys,
			Data: map[string]string{
				"access_key_id":     "LTAI-real-id",
				"access_key_secret": "real-secret",
			},
		},
	}
	b.handleGateway(context.Background(), req)

	assert.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
}

// --- extractToken / transparent auth role extraction ---

func TestExtractToken(t *testing.T) {
	t.Run("JWT from x-acs-security-token", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set(HeaderACSSecurityToken, "eyJxxx")
		r.Header.Set(HeaderAuthorization, "ACS3-HMAC-SHA256 Credential=anything,SignedHeaders=host,Signature=s")
		assert.Equal(t, "eyJxxx", extractToken(r))
	})

	t.Run("role from ACS3 Credential", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set(HeaderAuthorization, "ACS3-HMAC-SHA256 Credential=my-role,SignedHeaders=host,Signature=s")
		assert.Equal(t, "my-role", extractToken(r))
	})

	t.Run("non-ACS3 request returns empty", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set(HeaderAuthorization, "Bearer abc")
		assert.Equal(t, "", extractToken(r))
	})

	t.Run("no auth header returns empty", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/", nil)
		assert.Equal(t, "", extractToken(r))
	})
}

func TestGetAuthRoleFromRequest(t *testing.T) {
	b := setupBackend(t)

	t.Run("role from ACS3 Credential (cert flow)", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set(HeaderAuthorization, "ACS3-HMAC-SHA256 Credential=my-role,SignedHeaders=host,Signature=s")
		role, ok := b.GetAuthRoleFromRequest(r)
		assert.True(t, ok)
		assert.Equal(t, "my-role", role)
	})

	// Multi-role JWT flow: JWT in x-acs-security-token, role name in access_key_id.
	// This is what lets nginx drop the hardcoded role — Warden picks the role
	// from the signed Credential field per request.
	t.Run("role from ACS3 Credential (JWT flow)", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set(HeaderAuthorization, "ACS3-HMAC-SHA256 Credential=readonly,SignedHeaders=host,Signature=s")
		r.Header.Set(HeaderACSSecurityToken, "eyJabc.payload.sig") // JWT lives here, not in access_key_id
		role, ok := b.GetAuthRoleFromRequest(r)
		assert.True(t, ok, "role must resolve even when a JWT is present in x-acs-security-token")
		assert.Equal(t, "readonly", role)
	})

	t.Run("JWT misplaced in access_key_id is rejected", func(t *testing.T) {
		// Defensive: if a client puts the JWT in the Credential field instead
		// of in x-acs-security-token, we refuse to treat it as a role name.
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set(HeaderAuthorization, "ACS3-HMAC-SHA256 Credential=eyJabc,SignedHeaders=host,Signature=s")
		_, ok := b.GetAuthRoleFromRequest(r)
		assert.False(t, ok)
	})

	t.Run("non-ACS3 request", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set(HeaderAuthorization, "Bearer abc")
		_, ok := b.GetAuthRoleFromRequest(r)
		assert.False(t, ok)
	})
}

func TestPaths(t *testing.T) {
	b := setupBackend(t)
	paths := b.paths()
	require.Len(t, paths, 1)
	assert.Equal(t, "config", paths[0].Pattern)

	_, hasRead := paths[0].Operations[logical.ReadOperation]
	_, hasUpdate := paths[0].Operations[logical.UpdateOperation]
	assert.True(t, hasRead)
	assert.True(t, hasUpdate)

	for _, f := range []string{"max_body_size", "timeout", "auto_auth_path", "default_role", "tls_skip_verify", "ca_data"} {
		assert.Contains(t, paths[0].Fields, f)
	}
}
