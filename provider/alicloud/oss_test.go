package alicloud

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/sdk/sigv4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rewritingTransport rewrites the target URL host of an outgoing request to
// route it to the test server, while preserving the original Host header so
// signature computation still uses the Alicloud virtual host.
type rewritingTransport struct {
	inner  http.RoundTripper
	target *url.URL
}

func (rt *rewritingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r2 := r.Clone(r.Context())
	r2.URL.Scheme = rt.target.Scheme
	r2.URL.Host = rt.target.Host
	// r2.Host preserved (= original Alicloud host) so tests assert on what was signed
	return rt.inner.RoundTrip(r2)
}

// signOSSRequest signs an HTTP request using AWS SigV4 (S3-compatible mode),
// simulating what an Alicloud OSS client SDK would do in AWS-compatible mode.
func signOSSRequest(t *testing.T, method, rawURL, body, accessKeyID, secretAccessKey, securityToken, region string) *http.Request {
	t.Helper()
	bodyBytes := []byte(body)
	r := httptest.NewRequest(method, rawURL, strings.NewReader(body))
	r.ContentLength = int64(len(bodyBytes))

	payloadHash := sigv4.ComputePayloadHash(bodyBytes)
	r.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if securityToken != "" {
		r.Header.Set("X-Amz-Security-Token", securityToken)
	}

	creds := aws.Credentials{
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
	}
	signer := v4.NewSigner(func(o *v4.SignerOptions) {
		o.DisableURIPathEscaping = true
	})
	if err := signer.SignHTTP(context.Background(), creds, r, payloadHash, "s3", region, time.Now().UTC()); err != nil {
		t.Fatalf("signing OSS request: %v", err)
	}
	return r
}

func TestHandleOSS_CertTransparent_ForwardsSigned(t *testing.T) {
	var receivedAuth string
	var receivedHost string

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		receivedHost = r.Host
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	b := setupBackend(t)
	upURL, _ := url.Parse(upstream.URL)
	b.Proxy.Transport = &rewritingTransport{inner: upstream.Client().Transport, target: upURL}

	// Cert transparent: client signs using role name as both keys
	r := signOSSRequest(t, "GET", "https://oss-cn-hangzhou.aliyuncs.com/my-bucket/my-object", "", "role-reader", "role-reader", "", "cn-hangzhou")
	r.Host = "oss-cn-hangzhou.aliyuncs.com"

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

	// Upstream must see the request re-signed with the REAL credentials
	assert.True(t, strings.HasPrefix(receivedAuth, "AWS4-HMAC-SHA256"), "must be SigV4 signed: %q", receivedAuth)
	assert.Contains(t, receivedAuth, "Credential=LTAI-real-id", "must use real access_key_id")
	assert.NotContains(t, receivedAuth, "Credential=role-reader")
	// Host must be rewritten to the OSS regional endpoint
	assert.Contains(t, receivedHost, "oss-cn-hangzhou.aliyuncs.com")
}

func TestHandleOSS_JWTTransparent_ForwardsSigned(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// JWT must not leak upstream
		assert.NotContains(t, r.Header.Get("X-Amz-Security-Token"), "eyJ", "JWT must not be forwarded")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	b := setupBackend(t)
	upURL, _ := url.Parse(upstream.URL)
	b.Proxy.Transport = &rewritingTransport{inner: upstream.Client().Transport, target: upURL}

	jwt := "eyJhbGciOiJIUzI1NiJ9.payload.sig"
	r := signOSSRequest(t, "GET", "https://oss-cn-hangzhou.aliyuncs.com/my-bucket/key", "", "any-id", jwt, jwt, "cn-hangzhou")
	r.Host = "oss-cn-hangzhou.aliyuncs.com"

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

func TestHandleOSS_SignatureMismatch(t *testing.T) {
	b := setupBackend(t)

	r := signOSSRequest(t, "GET", "https://oss-cn-hangzhou.aliyuncs.com/my-bucket/key", "", "role-reader", "role-reader", "", "cn-hangzhou")
	r.Host = "oss-cn-hangzhou.aliyuncs.com"
	// Tamper with the signature
	auth := r.Header.Get("Authorization")
	r.Header.Set("Authorization", strings.Replace(auth, "Signature=", "Signature=deadbeef", 1))

	rec := httptest.NewRecorder()
	req := &logical.Request{
		HTTPRequest:    r,
		ResponseWriter: rec,
		Credential: &credential.Credential{
			Type: credential.TypeAlicloudKeys,
			Data: map[string]string{"access_key_id": "LTAI-real", "access_key_secret": "real"},
		},
	}
	b.handleGateway(context.Background(), req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestHandleOSS_MissingCredential(t *testing.T) {
	b := setupBackend(t)

	r := signOSSRequest(t, "GET", "https://oss-cn-hangzhou.aliyuncs.com/my-bucket/key", "", "role-reader", "role-reader", "", "cn-hangzhou")
	r.Host = "oss-cn-hangzhou.aliyuncs.com"

	rec := httptest.NewRecorder()
	req := &logical.Request{HTTPRequest: r, ResponseWriter: rec}
	b.handleGateway(context.Background(), req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestOSSEndpoint(t *testing.T) {
	cases := []struct {
		region   string
		incoming string
		want     string
	}{
		{"cn-hangzhou", "", "oss-cn-hangzhou.aliyuncs.com"},
		{"cn-hangzhou", "oss-cn-hangzhou.aliyuncs.com", "oss-cn-hangzhou.aliyuncs.com"},
		{"cn-hangzhou", "my-bucket.oss-cn-hangzhou.aliyuncs.com", "my-bucket.oss-cn-hangzhou.aliyuncs.com"},
		{"us-west-1", "some-bucket.oss-us-west-1.aliyuncs.com", "some-bucket.oss-us-west-1.aliyuncs.com"},
		{"cn-beijing", "totally-unrelated.example.com", "oss-cn-beijing.aliyuncs.com"},
	}
	for _, tc := range cases {
		got := ossEndpoint(tc.region, tc.incoming)
		assert.Equal(t, tc.want, got, "region=%s incoming=%s", tc.region, tc.incoming)
	}
}

// Compile-time check that extractToken handles all 4 transparent modes.
func TestExtractToken_DualMode(t *testing.T) {
	t.Run("OSS JWT from X-Amz-Security-Token", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("X-Amz-Security-Token", "eyJhbg.jwt.sig")
		r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=x/20240101/us-east-1/s3/aws4_request,SignedHeaders=host,Signature=s")
		assert.Equal(t, "eyJhbg.jwt.sig", extractToken(r))
	})

	t.Run("OSS role from SigV4 Credential", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=my-role/20240101/cn-hangzhou/s3/aws4_request,SignedHeaders=host,Signature=s")
		assert.Equal(t, "my-role", extractToken(r))
	})
}
