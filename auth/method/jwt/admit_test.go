package jwt

import (
	"context"
	"crypto/ecdsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/auth/helper"
	"github.com/stephnangue/warden/helper/selector"
	"github.com/stephnangue/warden/logical"
)

// admitRequest routes introspect/admit to b with token as the bearer, marked
// internal as core marks it when internal is set.
func admitRequest(t *testing.T, b *jwtAuthBackend, token string, internal bool) *logical.Response {
	t.Helper()
	resp, err := routeAdmit(b, token, internal)
	require.NoError(t, err)
	require.NotNil(t, resp)
	return resp
}

func routeAdmit(b *jwtAuthBackend, token string, internal bool) (*logical.Response, error) {
	httpReq := httptest.NewRequest(http.MethodGet, "/v1/auth/jwt/introspect/admit", nil)
	if token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+token)
	}
	return b.HandleRequest(context.Background(), &logical.Request{
		Operation:   logical.ReadOperation,
		Path:        helper.AdmitPattern,
		HTTPRequest: httpReq,
		Internal:    internal,
	})
}

// admitted returns the admission an admit response carries, or nil.
func admitted(t *testing.T, resp *logical.Response) *logical.Admission {
	t.Helper()
	require.NoError(t, resp.Err)
	ok, _ := resp.Data[helper.AdmittedKey].(bool)
	adm, _ := resp.Data[helper.AdmissionKey].(*logical.Admission)
	assert.Equal(t, ok, adm != nil, "admitted and admission agree")
	return adm
}

func TestAdmit_RefusedUnlessInternal(t *testing.T) {
	b, key := factsBackend(t, nil)
	token := signES256(t, key, baseClaims(nil))

	resp := admitRequest(t, b, token, false)
	require.Error(t, resp.Err)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.NotContains(t, resp.Data, helper.AdmissionKey)

	assert.NotContains(t, b.PathsSpecial.Unauthenticated, helper.AdmitPattern)
}

func TestAdmit_Valid(t *testing.T) {
	b, key := factsBackend(t, map[string]any{"facts": map[string]any{"repository": "repo"}})
	token := signES256(t, key, baseClaims(map[string]any{"repository": "acme/infra"}))

	adm := admitted(t, admitRequest(t, b, token, true))
	require.NotNil(t, adm)
	assert.Empty(t, adm.MountPath, "core names the mount")
	assert.Same(t, b.mountFacts, adm.Mount)
	assert.False(t, adm.IssuedAt.IsZero())
	n := adm.Mount.Load()
	cur := adm.Lookup(n, "repo")
	v, ok := cur.Next()
	require.True(t, ok)
	assert.Equal(t, "acme/infra", v.S)
	cur = adm.Facts.Lookup(selector.Key{Name: "sub"})
	v, _ = cur.Next()
	assert.Equal(t, "agent-1", v.S)
}

func TestAdmit_NotAdmitted(t *testing.T) {
	b, key := factsBackend(t, map[string]any{"bound_claims": map[string]any{"env": "prod"}})
	otherKey, _ := genTestPubKeyPEM(t, "ECDSA")
	prod := map[string]any{"env": "prod"}

	cases := map[string]string{
		"no credential":   "",
		"other signer":    signES256(t, otherKey.(*ecdsa.PrivateKey), baseClaims(prod)),
		"wrong audience":  signES256(t, key, baseClaims(map[string]any{"env": "prod", "aud": "someone-else"})),
		"wrong issuer":    signES256(t, key, baseClaims(map[string]any{"env": "prod", "iss": "https://other.example.com"})),
		"bound claims":    signES256(t, key, baseClaims(map[string]any{"env": "dev"})),
		"no principal":    signES256(t, key, baseClaims(map[string]any{"env": "prod", "sub": ""})),
		"expired":         signES256(t, key, baseClaims(map[string]any{"env": "prod", "exp": time.Now().Add(-time.Hour).Unix()})),
		"not a JWT":       "not-a-jwt",
		"audience absent": signES256(t, key, deleteClaim(baseClaims(prod), "aud")),
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			assert.Nil(t, admitted(t, admitRequest(t, b, token, true)))
		})
	}
	// The same token with the bound claim is admitted.
	assert.NotNil(t, admitted(t, admitRequest(t, b, signES256(t, key, baseClaims(prod)), true)))
}

func deleteClaim(c map[string]any, name string) map[string]any {
	delete(c, name)
	return c
}

// An unconfigured mount cannot decide: an error, which discovery reports as the
// mount's warning. Without a credential there is nothing to decide.
func TestAdmit_Unconfigured(t *testing.T) {
	b, _ := createTestBackendWithStorage(t)
	resp, err := routeAdmit(b, "eyJ.a.b", true)
	assert.ErrorIs(t, err, errNotConfigured)
	assert.ErrorIs(t, err, helper.ErrAdmitNotConfigured, "discovery reports the class")
	assert.Nil(t, resp)
	assert.Nil(t, admitted(t, admitRequest(t, b, "", true)))
}

// The mount's max_age is enforced at admission: a stale token and one without
// iat are refused; role logins are not affected (TestConfig_MaxAgeNotUsedByLogins).
func TestAdmit_MaxAge(t *testing.T) {
	b, key := factsBackend(t, map[string]any{"max_age": "10m"})
	ctx := context.Background()
	now := time.Now()
	b.configMu.RLock()
	config := b.config
	b.configMu.RUnlock()

	fresh := signES256(t, key, baseClaims(map[string]any{"iat": now.Add(-time.Minute).Unix()}))
	stale := signES256(t, key, baseClaims(map[string]any{"iat": now.Add(-20 * time.Minute).Unix()}))
	// Without iat the validator needs nbf, or it puts nbf just before exp.
	noIat := signES256(t, key, deleteClaim(baseClaims(map[string]any{"nbf": now.Add(-time.Minute).Unix()}), "iat"))

	_, err := admitToken(ctx, config, fresh, now)
	assert.NoError(t, err)
	_, err = admitToken(ctx, config, stale, now)
	assert.ErrorContains(t, err, "max_age")
	_, err = admitToken(ctx, config, noIat, now)
	assert.ErrorIs(t, err, helper.ErrNoIssueTime)

	// The fresh token ages out as now moves on.
	_, err = admitToken(ctx, config, fresh, now.Add(10*time.Minute))
	assert.ErrorContains(t, err, "max_age")

	assert.NotNil(t, admitted(t, admitRequest(t, b, fresh, true)))
	assert.Nil(t, admitted(t, admitRequest(t, b, stale, true)))
	assert.Nil(t, admitted(t, admitRequest(t, b, noIat, true)))
}

// Admission uses the mount's bound_audiences, any one of them.
func TestAdmit_MountAudiences(t *testing.T) {
	b, key := factsBackend(t, map[string]any{"bound_audiences": []string{"warden", "warden-b"}})
	assert.NotNil(t, admitted(t, admitRequest(t, b, signES256(t, key, baseClaims(map[string]any{"aud": "warden-b"})), true)))
	assert.Nil(t, admitted(t, admitRequest(t, b, signES256(t, key, baseClaims(map[string]any{"aud": "someone-else"})), true)))
}

// expectedClaims is the mount's issuer, subject and audiences.
func TestExpectedClaims(t *testing.T) {
	config := &JWTAuthConfig{BoundIssuer: "iss", BoundSubject: "msub", BoundAudiences: []string{"maud"}}
	e := expectedClaims(config)
	assert.Equal(t, "iss", e.Issuer)
	assert.Equal(t, "msub", e.Subject)
	assert.Equal(t, []string{"maud"}, e.Audiences)

	e = expectedClaims(&JWTAuthConfig{BoundAudiences: []string{}})
	assert.Nil(t, e.Audiences, "an empty list leaves the audience unchecked")
	assert.NotEmpty(t, e.SigningAlgorithms)
}

func TestExtractJWTFromRequest(t *testing.T) {
	t.Run("from Authorization header", func(t *testing.T) {
		httpReq := httptest.NewRequest(http.MethodGet, "/foo", nil)
		httpReq.Header.Set("Authorization", "Bearer eyJ.payload.sig")
		assert.Equal(t, "eyJ.payload.sig", extractJWTFromRequest(&logical.Request{HTTPRequest: httpReq}))
	})
	t.Run("scheme is case-insensitive, as on the gateway", func(t *testing.T) {
		for _, scheme := range []string{"bearer ", "BEARER ", "bEaReR "} {
			httpReq := httptest.NewRequest(http.MethodGet, "/foo", nil)
			httpReq.Header.Set("Authorization", scheme+"eyJ.payload.sig")
			assert.Equal(t, "eyJ.payload.sig", extractJWTFromRequest(&logical.Request{HTTPRequest: httpReq}), scheme)
		}
	})
	t.Run("no Bearer prefix → empty", func(t *testing.T) {
		httpReq := httptest.NewRequest(http.MethodGet, "/foo", nil)
		httpReq.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
		assert.Equal(t, "", extractJWTFromRequest(&logical.Request{HTTPRequest: httpReq}))
	})
	t.Run("falls back to ClientToken when no HTTP request", func(t *testing.T) {
		assert.Equal(t, "eyJ.client.token", extractJWTFromRequest(&logical.Request{ClientToken: "eyJ.client.token"}))
	})
	t.Run("empty when neither present", func(t *testing.T) {
		assert.Equal(t, "", extractJWTFromRequest(&logical.Request{}))
	})
}
