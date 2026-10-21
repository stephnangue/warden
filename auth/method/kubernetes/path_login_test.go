package kubernetes

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

// loginSetup builds a backend wired to a fake apiserver returning the
// given TokenReview status. Returns the backend and the fake apiserver handle.
func loginSetup(t *testing.T, status tokenReviewStatus, configOverrides map[string]any) (*kubernetesAuthBackend, *fakeAPIServer) {
	t.Helper()
	b, ctx := newTestBackend(t)
	fake := newFakeAPIServer(t, fakeAPIServerOpts{Response: status})

	cfg := map[string]any{
		"kubernetes_host": fake.URL,
		"tls_skip_verify": true,
	}
	for k, v := range configOverrides {
		cfg[k] = v
	}
	require.NoError(t, b.setupConfig(ctx, cfg))
	return b, fake
}

func loginFieldData(t *testing.T, b *kubernetesAuthBackend, jwt string) *framework.FieldData {
	t.Helper()
	return &framework.FieldData{
		Raw:    map[string]any{"jwt": jwt},
		Schema: b.pathLogin().Fields,
	}
}

func TestHandleLogin_HappyPath_SelfReviewingMode(t *testing.T) {
	b, fake := loginSetup(t, tokenReviewStatus{
		Authenticated: true,
		User:          tokenReviewUser{Username: "system:serviceaccount:default:myapp", UID: "uid-1"},
	}, nil)

	jwt := mintK8sSAJWT("https://kube", "default", "myapp")
	ctx := t.Context()
	resp, err := b.handleLogin(ctx, &logical.Request{ClientIP: "10.0.0.1"}, loginFieldData(t, b, jwt))
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Nil(t, resp.Err, "unexpected login error: %v", resp.Err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	require.NotNil(t, resp.Auth)
	assert.Equal(t, "system:serviceaccount:default:myapp", resp.Auth.PrincipalID)
	assert.Equal(t, "kubernetes_role", resp.Auth.TokenType)
	assert.Nil(t, resp.Auth.Policies, "a login is an admission: no policies")
	assert.Nil(t, resp.Auth.Metadata, "a login is an admission: no metadata")
	assert.Equal(t, jwt, resp.Auth.ClientToken, "ClientToken must be the raw workload JWT for transparent-mode cache lookups")
	require.NotNil(t, resp.Auth.Admission)
	assert.Same(t, b.mountFacts, resp.Auth.Admission.Mount)
	assert.NotContains(t, resp.Data, "role")

	// In self-reviewing mode the workload JWT IS the Authorization bearer.
	assert.Equal(t, "Bearer "+jwt, fake.BearerSeen)

	// Data surfaces the parsed SA fields for audit consumers.
	assert.Equal(t, "default", resp.Data["service_account_namespace"])
	assert.Equal(t, "myapp", resp.Data["service_account_name"])
	assert.Equal(t, "uid-1", resp.Data["service_account_uid"])
}

func TestHandleLogin_UsesTokenReviewerJWTAsBearerWhenConfigured(t *testing.T) {
	b, fake := loginSetup(t, tokenReviewStatus{
		Authenticated: true,
		User:          tokenReviewUser{Username: "system:serviceaccount:default:myapp"},
	}, map[string]any{
		"token_reviewer_jwt": "hub-reviewer-jwt",
	})

	jwt := mintK8sSAJWT("https://kube", "default", "myapp")
	_, _ = b.handleLogin(t.Context(), &logical.Request{}, loginFieldData(t, b, jwt))

	assert.Equal(t, "Bearer hub-reviewer-jwt", fake.BearerSeen,
		"configured token_reviewer_jwt must be used as the Authorization bearer")
	assert.Equal(t, jwt, fake.TokenSeen, "workload JWT goes in spec.token regardless of bearer choice")
}

func TestHandleLogin_RejectsWhenTokenReviewSaysUnauthenticated(t *testing.T) {
	b, _ := loginSetup(t, tokenReviewStatus{
		Authenticated: false,
		Error:         "token signature invalid",
	}, nil)

	jwt := mintK8sSAJWT("https://kube", "default", "myapp")
	resp, err := b.handleLogin(t.Context(), &logical.Request{}, loginFieldData(t, b, jwt))
	require.NoError(t, err)
	require.NotNil(t, resp.Err)
	assert.Equal(t, errAuthFailed.Error(), resp.Err.Error(),
		"all auth failures must collapse to errAuthFailed (no info leak)")
}

func TestHandleLogin_RejectsNonServiceAccountUsername(t *testing.T) {
	b, _ := loginSetup(t, tokenReviewStatus{
		Authenticated: true,
		User:          tokenReviewUser{Username: "system:anonymous"},
	}, nil)

	jwt := mintK8sSAJWT("https://kube", "default", "myapp")
	resp, err := b.handleLogin(t.Context(), &logical.Request{}, loginFieldData(t, b, jwt))
	require.NoError(t, err)
	require.NotNil(t, resp.Err)
	assert.Equal(t, errAuthFailed.Error(), resp.Err.Error())
}

// Any service account the review authenticates is admitted: which ones get a
// role is the groups' decision, not the mount's.
func TestHandleLogin_AdmitsAnyReviewedServiceAccount(t *testing.T) {
	b, _ := loginSetup(t, tokenReviewStatus{
		Authenticated: true,
		User:          tokenReviewUser{Username: "system:serviceaccount:other-ns:myapp"},
	}, nil)

	jwt := mintK8sSAJWT("https://kube", "other-ns", "myapp")
	resp, err := b.handleLogin(t.Context(), &logical.Request{}, loginFieldData(t, b, jwt))
	require.NoError(t, err)
	require.Nil(t, resp.Err)
	assert.Equal(t, "system:serviceaccount:other-ns:myapp", resp.Auth.PrincipalID)
}

func TestHandleLogin_IssuerPreFilter_RejectsMismatchedIss(t *testing.T) {
	b, fake := loginSetup(t, tokenReviewStatus{
		Authenticated: true,
		User:          tokenReviewUser{Username: "system:serviceaccount:default:myapp"},
	}, map[string]any{
		"issuer": "https://cluster-a.svc",
	})

	// Token from a different cluster.
	jwt := mintK8sSAJWT("https://cluster-b.svc", "default", "myapp")
	resp, err := b.handleLogin(t.Context(), &logical.Request{}, loginFieldData(t, b, jwt))
	require.NoError(t, err)
	require.NotNil(t, resp.Err)
	assert.Equal(t, errAuthFailed.Error(), resp.Err.Error())
	assert.Equal(t, int32(0), fake.Calls,
		"issuer pre-filter must reject before the TokenReview round-trip")
}

func TestHandleLogin_IssuerPreFilter_AcceptsMatchingIss(t *testing.T) {
	b, fake := loginSetup(t, tokenReviewStatus{
		Authenticated: true,
		User:          tokenReviewUser{Username: "system:serviceaccount:default:myapp"},
	}, map[string]any{
		"issuer": "https://cluster-a.svc",
	})

	jwt := mintK8sSAJWT("https://cluster-a.svc", "default", "myapp")
	resp, err := b.handleLogin(t.Context(), &logical.Request{}, loginFieldData(t, b, jwt))
	require.NoError(t, err)
	require.Nil(t, resp.Err)
	assert.Equal(t, int32(1), fake.Calls, "matching iss should not block TokenReview")
}

// The mount's bound_audiences are sent as the review's spec.audiences, and a
// review that validated none of them does not admit.
func TestHandleLogin_PassesMountAudiencesToTokenReview(t *testing.T) {
	b, fake := loginSetup(t, tokenReviewStatus{
		Authenticated: true,
		User:          tokenReviewUser{Username: "system:serviceaccount:default:myapp"},
		Audiences:     []string{"https://my-api"},
	}, map[string]any{"bound_audiences": []string{"https://my-api"}})

	jwt := mintK8sSAJWT("https://kube", "default", "myapp")
	resp, err := b.handleLogin(t.Context(), &logical.Request{}, loginFieldData(t, b, jwt))
	require.NoError(t, err)
	require.Nil(t, resp.Err)
	assert.Equal(t, []string{"https://my-api"}, fake.AudsSeen,
		"the mount's bound_audiences must be passed through as spec.audiences")

	other, _ := loginSetup(t, tokenReviewStatus{
		Authenticated: true,
		User:          tokenReviewUser{Username: "system:serviceaccount:default:myapp"},
		Audiences:     []string{"https://kubernetes.default.svc"},
	}, map[string]any{"bound_audiences": []string{"https://my-api"}})
	resp, err = other.handleLogin(t.Context(), &logical.Request{}, loginFieldData(t, other, jwt))
	require.NoError(t, err)
	require.NotNil(t, resp.Err, "a review that validated another audience does not admit")
	assert.Equal(t, errAuthFailed.Error(), resp.Err.Error())
}

func TestHandleLogin_TTLClampsToJWTExp(t *testing.T) {
	b, _ := loginSetup(t, tokenReviewStatus{
		Authenticated: true,
		User:          tokenReviewUser{Username: "system:serviceaccount:default:myapp"},
	}, map[string]any{"token_ttl": 3600})

	// JWT expires in 10 minutes — effective TTL should clamp to that, not 1h.
	exp := time.Now().Add(10 * time.Minute).Unix()
	jwt := mintJWT(map[string]any{
		"iss": "https://kube",
		"sub": "system:serviceaccount:default:myapp",
		"exp": float64(exp),
	})

	resp, err := b.handleLogin(t.Context(), &logical.Request{}, loginFieldData(t, b, jwt))
	require.NoError(t, err)
	require.NotNil(t, resp.Auth)
	// Allow ±30s wiggle around the 10m expectation.
	assert.InDelta(t, (10 * time.Minute).Seconds(), resp.Auth.TokenTTL.Seconds(), 30,
		"TTL should clamp to JWT exp when sooner than the mount's token_ttl")

	// A later exp is capped by the mount's token_ttl.
	far := mintJWT(map[string]any{
		"iss": "https://kube",
		"sub": "system:serviceaccount:default:myapp",
		"exp": float64(time.Now().Add(5 * time.Hour).Unix()),
	})
	resp, err = b.handleLogin(t.Context(), &logical.Request{}, loginFieldData(t, b, far))
	require.NoError(t, err)
	require.NotNil(t, resp.Auth)
	assert.Equal(t, time.Hour, resp.Auth.TokenTTL)
}

// The mount's max_age is enforced at login: a token issued longer ago, or
// without an iat, is not admitted; a fresh one is.
func TestHandleLogin_RejectsTokenOlderThanMountMaxAge(t *testing.T) {
	b, _ := loginSetup(t, tokenReviewStatus{
		Authenticated: true,
		User:          tokenReviewUser{Username: "system:serviceaccount:default:myapp"},
	}, map[string]any{"max_age": "5m"})

	for name, claims := range map[string]map[string]any{
		"older than max_age": {"iat": float64(time.Now().Add(-10 * time.Minute).Unix())},
		"no iat":             {},
	} {
		claims["iss"] = "https://kube"
		claims["sub"] = "system:serviceaccount:default:myapp"
		resp, err := b.handleLogin(t.Context(), &logical.Request{}, loginFieldData(t, b, mintJWT(claims)))
		require.NoError(t, err)
		require.NotNil(t, resp.Err, name)
		assert.Equal(t, errAuthFailed.Error(), resp.Err.Error(), name)
	}

	fresh := mintJWT(map[string]any{
		"iss": "https://kube",
		"sub": "system:serviceaccount:default:myapp",
		"iat": float64(time.Now().Add(-time.Minute).Unix()),
	})
	resp, err := b.handleLogin(t.Context(), &logical.Request{}, loginFieldData(t, b, fresh))
	require.NoError(t, err)
	require.Nil(t, resp.Err)
}

func TestHandleLogin_BasicValidation(t *testing.T) {
	b, ctx := newTestBackend(t)

	t.Run("missing jwt", func(t *testing.T) {
		require.NoError(t, b.setupConfig(ctx, map[string]any{
			"kubernetes_host": "https://kube",
			"tls_skip_verify": true,
		}))
		d := &framework.FieldData{Raw: map[string]any{}, Schema: b.pathLogin().Fields}
		resp, err := b.handleLogin(ctx, &logical.Request{}, d)
		require.NoError(t, err)
		require.NotNil(t, resp.Err)
		assert.Contains(t, resp.Err.Error(), "jwt is required")
	})

	t.Run("no role field", func(t *testing.T) {
		_, ok := b.pathLogin().Fields["role"]
		assert.False(t, ok, "a login selects no role")
	})

	t.Run("backend not configured", func(t *testing.T) {
		fresh, freshCtx := newTestBackend(t)
		d := &framework.FieldData{Raw: map[string]any{"jwt": "x"}, Schema: fresh.pathLogin().Fields}
		resp, err := fresh.handleLogin(freshCtx, &logical.Request{}, d)
		require.NoError(t, err)
		require.NotNil(t, resp.Err)
		assert.Contains(t, resp.Err.Error(), "not configured")
	})
}

// A mount without bound_audiences admits through the API server's audience,
// and its config read says so; one with them does not warn.
func TestConfigRead_WarnsWithoutBoundAudiences(t *testing.T) {
	b, _ := loginSetup(t, tokenReviewStatus{}, nil)
	resp, err := b.handleConfigRead(t.Context(), &logical.Request{}, &framework.FieldData{})
	require.NoError(t, err)
	// In the data, the one place an HTTP client sees it.
	warnings, _ := resp.Data["warnings"].([]string)
	require.Len(t, warnings, 1)
	assert.Contains(t, warnings[0], "bound_audiences is empty")

	bound, _ := loginSetup(t, tokenReviewStatus{}, map[string]any{"bound_audiences": []string{"warden"}})
	resp, err = bound.handleConfigRead(t.Context(), &logical.Request{}, &framework.FieldData{})
	require.NoError(t, err)
	assert.NotContains(t, resp.Data, "warnings")
}

// A config write that leaves bound_audiences empty warns as the read does; one
// that sets them, or keeps them set, does not.
func TestConfigWrite_WarnsWithoutBoundAudiences(t *testing.T) {
	b, ctx := newTestBackend(t)
	write := func(raw map[string]any) *logical.Response {
		t.Helper()
		resp, err := b.handleConfigWrite(ctx, nil, &framework.FieldData{Raw: raw, Schema: b.pathConfig().Fields})
		require.NoError(t, err)
		require.NoError(t, resp.Err)
		assert.Equal(t, "configuration updated", resp.Data["message"])
		return resp
	}

	resp := write(map[string]any{"kubernetes_host": "https://kube", "tls_skip_verify": true})
	// In the data, the one place an HTTP client sees it.
	assert.Equal(t, []string{noAudiencesWarning}, resp.Data["warnings"])

	resp = write(map[string]any{"bound_audiences": []string{"warden"}})
	assert.NotContains(t, resp.Data, "warnings")

	resp = write(map[string]any{"issuer": "https://kube"})
	assert.NotContains(t, resp.Data, "warnings", "audiences kept from the stored config")

	resp = write(map[string]any{"bound_audiences": ""})
	assert.Equal(t, []string{noAudiencesWarning}, resp.Data["warnings"], "an empty value clears the list")
}
