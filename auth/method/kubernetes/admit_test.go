package kubernetes

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/auth/helper"
	"github.com/stephnangue/warden/logical"
)

// admitRequest routes introspect/admit to b with token as the bearer, marked
// internal as core marks it when internal is set.
func admitRequest(t *testing.T, b *kubernetesAuthBackend, token string, internal bool) *logical.Response {
	t.Helper()
	httpReq := httptest.NewRequest(http.MethodGet, "/v1/auth/kubernetes/introspect/admit", nil)
	if token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation:   logical.ReadOperation,
		Path:        helper.AdmitPattern,
		HTTPRequest: httpReq,
		Internal:    internal,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	return resp
}

func admitted(t *testing.T, resp *logical.Response) *logical.Admission {
	t.Helper()
	require.NoError(t, resp.Err)
	ok, _ := resp.Data[helper.AdmittedKey].(bool)
	adm, _ := resp.Data[helper.AdmissionKey].(*logical.Admission)
	assert.Equal(t, ok, adm != nil)
	return adm
}

func lookup(adm *logical.Admission, name string) []string {
	cur := adm.Lookup(adm.Mount.Load(), name)
	var out []string
	for v, ok := cur.Next(); ok; v, ok = cur.Next() {
		out = append(out, v.S)
	}
	return out
}

func TestAdmit_RefusedUnlessInternal(t *testing.T) {
	b := reviewingBackend(t, map[string]any{"bound_audiences": []string{"warden"}})
	resp := admitRequest(t, b, saToken("default", "myapp", []string{"warden"}, nil), false)
	require.Error(t, resp.Err)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.NotContains(t, resp.Data, helper.AdmissionKey)
	assert.NotContains(t, b.PathsSpecial.Unauthenticated, helper.AdmitPattern)
}

func TestAdmit_Valid(t *testing.T) {
	b := reviewingBackend(t, map[string]any{
		"bound_audiences": []string{"warden"},
		"facts":           map[string]any{"username": "workload"},
	})
	token := saToken("ci", "deployer", []string{"warden", "other"}, map[string]any{"iat": time.Now().Unix()})
	adm := admitted(t, admitRequest(t, b, token, true))
	require.NotNil(t, adm)
	assert.Same(t, b.mountFacts, adm.Mount)
	assert.Empty(t, adm.MountPath)
	assert.False(t, adm.IssuedAt.IsZero())
	assert.Equal(t, []string{"system:serviceaccount:ci:deployer"}, lookup(adm, "workload"))
	assert.Equal(t, []string{"warden"}, lookup(adm, "aud"), "the audiences the review validated")
}

func TestAdmit_NotAdmitted(t *testing.T) {
	b := reviewingBackend(t, map[string]any{"bound_audiences": []string{"warden"}})
	cases := map[string]string{
		"no credential":         "",
		"wrong audience":        saToken("default", "myapp", []string{"someone-else"}, nil),
		"API server audience":   saToken("default", "myapp", []string{apiServerAudience}, nil),
		"not a service account": mintJWT(map[string]any{"sub": "system:node:n1", "aud": []string{"warden"}}),
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			assert.Nil(t, admitted(t, admitRequest(t, b, token, true)))
		})
	}
}

// Without bound_audiences the review validates against the API server's own
// audience, as a TokenReview naming none does.
func TestAdmit_NoBoundAudiences(t *testing.T) {
	b := reviewingBackend(t, nil)
	assert.NotNil(t, admitted(t, admitRequest(t, b, saToken("default", "myapp", []string{apiServerAudience}, nil), true)))
	assert.Nil(t, admitted(t, admitRequest(t, b, saToken("default", "myapp", []string{"warden"}, nil), true)))
}

// A reviewer that does not report one of the requested audiences back is not
// trusted to have checked them; one TokenReview per admission, none when the
// issuer pre-filter refuses.
func TestAdmit_ReviewerAudiencesAndCalls(t *testing.T) {
	b, ctx := newTestBackend(t)
	fake := newFakeAPIServer(t, fakeAPIServerOpts{Response: tokenReviewStatus{
		Authenticated: true,
		User:          tokenReviewUser{Username: "system:serviceaccount:default:myapp"},
		Audiences:     []string{apiServerAudience},
	}})
	require.NoError(t, b.setupConfig(ctx, map[string]any{
		"kubernetes_host": fake.URL,
		"tls_skip_verify": true,
		"bound_audiences": []string{"warden"},
		"issuer":          "https://kube",
	}))

	token := mintK8sSAJWT("https://kube", "default", "myapp")
	assert.Nil(t, admitted(t, admitRequest(t, b, token, true)))
	assert.Equal(t, int32(1), atomic.LoadInt32(&fake.Calls), "one TokenReview per admission")
	assert.Equal(t, []string{"warden"}, fake.AudsSeen, "the mount's bound_audiences are the review's audiences")

	assert.Nil(t, admitted(t, admitRequest(t, b, mintK8sSAJWT("https://elsewhere", "default", "myapp"), true)))
	assert.Equal(t, int32(1), atomic.LoadInt32(&fake.Calls), "the issuer pre-filter refuses before the review")
}

func TestAdmit_Unconfigured(t *testing.T) {
	b, _ := newTestBackend(t)
	assert.Nil(t, admitted(t, admitRequest(t, b, mintK8sSAJWT("https://kube", "default", "myapp"), true)))
}

// The mount's max_age is enforced at admission: a stale token and one without
// iat are refused.
func TestAdmit_MaxAge(t *testing.T) {
	b := reviewingBackend(t, map[string]any{"bound_audiences": []string{"warden"}, "max_age": "10m"})
	now := time.Now()
	b.configMu.RLock()
	cfg := b.config
	b.configMu.RUnlock()
	ctx := context.Background()

	fresh := saToken("default", "myapp", []string{"warden"}, map[string]any{"iat": now.Add(-time.Minute).Unix()})
	stale := saToken("default", "myapp", []string{"warden"}, map[string]any{"iat": now.Add(-20 * time.Minute).Unix()})
	noIat := saToken("default", "myapp", []string{"warden"}, nil)

	_, err := admitToken(ctx, cfg, fresh, now)
	assert.NoError(t, err)
	_, err = admitToken(ctx, cfg, stale, now)
	assert.ErrorContains(t, err, "max_age")
	_, err = admitToken(ctx, cfg, noIat, now)
	assert.ErrorIs(t, err, helper.ErrNoIssueTime)

	assert.NotNil(t, admitted(t, admitRequest(t, b, fresh, true)))
	assert.Nil(t, admitted(t, admitRequest(t, b, stale, true)))
	assert.Nil(t, admitted(t, admitRequest(t, b, noIat, true)))
}
