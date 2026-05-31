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
// given TokenReview status, plus a role with sensible defaults. Returns
// the backend, ctx, fake apiserver handle, and the role's name.
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

	// Default role: bound to default/myapp.
	_, err := b.handleRoleCreate(ctx, nil, roleFieldData(t, b, map[string]any{
		"name":                             "myrole",
		"bound_service_account_names":      []string{"myapp"},
		"bound_service_account_namespaces": []string{"default"},
		"token_policies":                   []string{"default"},
	}))
	require.NoError(t, err)
	return b, fake
}

func loginFieldData(t *testing.T, b *kubernetesAuthBackend, jwt, role string) *framework.FieldData {
	t.Helper()
	return &framework.FieldData{
		Raw:    map[string]any{"jwt": jwt, "role": role},
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
	resp, err := b.handleLogin(ctx, &logical.Request{ClientIP: "10.0.0.1"}, loginFieldData(t, b, jwt, "myrole"))
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Nil(t, resp.Err, "unexpected login error: %v", resp.Err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	require.NotNil(t, resp.Auth)
	assert.Equal(t, "system:serviceaccount:default:myapp", resp.Auth.PrincipalID)
	assert.Equal(t, "myrole", resp.Auth.RoleName)
	assert.Equal(t, "kubernetes_role", resp.Auth.TokenType)
	assert.Equal(t, []string{"default"}, resp.Auth.Policies)
	assert.Equal(t, jwt, resp.Auth.ClientToken, "ClientToken must be the raw workload JWT for transparent-mode cache lookups")

	// In self-reviewing mode the workload JWT IS the Authorization bearer.
	assert.Equal(t, "Bearer "+jwt, fake.BearerSeen)

	// Metadata surfaces the parsed SA fields for audit consumers.
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
	_, _ = b.handleLogin(t.Context(), &logical.Request{}, loginFieldData(t, b, jwt, "myrole"))

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
	resp, err := b.handleLogin(t.Context(), &logical.Request{}, loginFieldData(t, b, jwt, "myrole"))
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
	resp, err := b.handleLogin(t.Context(), &logical.Request{}, loginFieldData(t, b, jwt, "myrole"))
	require.NoError(t, err)
	require.NotNil(t, resp.Err)
	assert.Equal(t, errAuthFailed.Error(), resp.Err.Error())
}

func TestHandleLogin_RejectsSANotInRoleBindings(t *testing.T) {
	b, _ := loginSetup(t, tokenReviewStatus{
		Authenticated: true,
		User:          tokenReviewUser{Username: "system:serviceaccount:other-ns:myapp"},
	}, nil)

	jwt := mintK8sSAJWT("https://kube", "other-ns", "myapp")
	resp, err := b.handleLogin(t.Context(), &logical.Request{}, loginFieldData(t, b, jwt, "myrole"))
	require.NoError(t, err)
	require.NotNil(t, resp.Err)
	assert.Equal(t, errAuthFailed.Error(), resp.Err.Error())
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
	resp, err := b.handleLogin(t.Context(), &logical.Request{}, loginFieldData(t, b, jwt, "myrole"))
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
	resp, err := b.handleLogin(t.Context(), &logical.Request{}, loginFieldData(t, b, jwt, "myrole"))
	require.NoError(t, err)
	require.Nil(t, resp.Err)
	assert.Equal(t, int32(1), fake.Calls, "matching iss should not block TokenReview")
}

func TestHandleLogin_PassesRoleAudienceToTokenReview(t *testing.T) {
	b, ctx := newTestBackend(t)
	fake := newFakeAPIServer(t, fakeAPIServerOpts{
		Response: tokenReviewStatus{
			Authenticated: true,
			User:          tokenReviewUser{Username: "system:serviceaccount:default:myapp"},
		},
	})
	require.NoError(t, b.setupConfig(ctx, map[string]any{
		"kubernetes_host": fake.URL,
		"tls_skip_verify": true,
	}))
	// Role pins audience.
	_, _ = b.handleRoleCreate(ctx, nil, roleFieldData(t, b, map[string]any{
		"name":                             "audrole",
		"bound_service_account_names":      []string{"myapp"},
		"bound_service_account_namespaces": []string{"default"},
		"audience":                         "https://my-api",
	}))

	jwt := mintK8sSAJWT("https://kube", "default", "myapp")
	_, _ = b.handleLogin(ctx, &logical.Request{}, loginFieldData(t, b, jwt, "audrole"))

	assert.Equal(t, []string{"https://my-api"}, fake.AudsSeen,
		"role.audience must be passed through as spec.audiences")
}

func TestHandleLogin_TTLClampsToJWTExp(t *testing.T) {
	b, ctx := newTestBackend(t)
	fake := newFakeAPIServer(t, fakeAPIServerOpts{
		Response: tokenReviewStatus{
			Authenticated: true,
			User:          tokenReviewUser{Username: "system:serviceaccount:default:myapp"},
		},
	})
	require.NoError(t, b.setupConfig(ctx, map[string]any{
		"kubernetes_host": fake.URL,
		"tls_skip_verify": true,
	}))
	_, _ = b.handleRoleCreate(ctx, nil, roleFieldData(t, b, map[string]any{
		"name":                             "ttltest",
		"bound_service_account_names":      []string{"myapp"},
		"bound_service_account_namespaces": []string{"default"},
		"token_ttl":                        3600, // 1h
	}))

	// JWT expires in 10 minutes — effective TTL should clamp to that, not 1h.
	exp := time.Now().Add(10 * time.Minute).Unix()
	jwt := mintJWT(map[string]any{
		"iss": "https://kube",
		"sub": "system:serviceaccount:default:myapp",
		"exp": float64(exp),
	})

	resp, err := b.handleLogin(ctx, &logical.Request{}, loginFieldData(t, b, jwt, "ttltest"))
	require.NoError(t, err)
	require.NotNil(t, resp.Auth)
	// Allow ±30s wiggle around the 10m expectation.
	assert.InDelta(t, (10 * time.Minute).Seconds(), resp.Auth.TokenTTL.Seconds(), 30,
		"TTL should clamp to JWT exp when sooner than role.token_ttl")
}

func TestHandleLogin_RejectsTokenOlderThanMaxAge(t *testing.T) {
	b, ctx := newTestBackend(t)
	fake := newFakeAPIServer(t, fakeAPIServerOpts{
		Response: tokenReviewStatus{
			Authenticated: true,
			User:          tokenReviewUser{Username: "system:serviceaccount:default:myapp"},
		},
	})
	require.NoError(t, b.setupConfig(ctx, map[string]any{
		"kubernetes_host": fake.URL,
		"tls_skip_verify": true,
	}))
	_, _ = b.handleRoleCreate(ctx, nil, roleFieldData(t, b, map[string]any{
		"name":                             "maxagerole",
		"bound_service_account_names":      []string{"myapp"},
		"bound_service_account_namespaces": []string{"default"},
		"max_age":                          "5m",
	}))

	// Token issued 10 minutes ago, max_age=5m → rejected.
	iat := time.Now().Add(-10 * time.Minute).Unix()
	jwt := mintJWT(map[string]any{
		"iss": "https://kube",
		"sub": "system:serviceaccount:default:myapp",
		"iat": float64(iat),
	})

	resp, err := b.handleLogin(ctx, &logical.Request{}, loginFieldData(t, b, jwt, "maxagerole"))
	require.NoError(t, err)
	require.NotNil(t, resp.Err)
	assert.Equal(t, errAuthFailed.Error(), resp.Err.Error())
	_ = fake
}

func TestHandleLogin_DefaultRoleFallback(t *testing.T) {
	b, ctx := newTestBackend(t)
	fake := newFakeAPIServer(t, fakeAPIServerOpts{
		Response: tokenReviewStatus{
			Authenticated: true,
			User:          tokenReviewUser{Username: "system:serviceaccount:default:myapp"},
		},
	})
	require.NoError(t, b.setupConfig(ctx, map[string]any{
		"kubernetes_host": fake.URL,
		"tls_skip_verify": true,
		"default_role":    "fallback",
	}))
	_, _ = b.handleRoleCreate(ctx, nil, roleFieldData(t, b, map[string]any{
		"name":                             "fallback",
		"bound_service_account_names":      []string{"myapp"},
		"bound_service_account_namespaces": []string{"default"},
	}))

	jwt := mintK8sSAJWT("https://kube", "default", "myapp")
	// Note: no role in the request.
	d := &framework.FieldData{Raw: map[string]any{"jwt": jwt}, Schema: b.pathLogin().Fields}
	resp, err := b.handleLogin(ctx, &logical.Request{}, d)
	require.NoError(t, err)
	require.Nil(t, resp.Err)
	assert.Equal(t, "fallback", resp.Auth.RoleName)
}

func TestHandleLogin_BasicValidation(t *testing.T) {
	b, ctx := newTestBackend(t)

	t.Run("missing jwt", func(t *testing.T) {
		require.NoError(t, b.setupConfig(ctx, map[string]any{
			"kubernetes_host": "https://kube",
			"tls_skip_verify": true,
		}))
		d := &framework.FieldData{Raw: map[string]any{"role": "x"}, Schema: b.pathLogin().Fields}
		resp, err := b.handleLogin(ctx, &logical.Request{}, d)
		require.NoError(t, err)
		require.NotNil(t, resp.Err)
		assert.Contains(t, resp.Err.Error(), "jwt is required")
	})

	t.Run("missing role and no default", func(t *testing.T) {
		d := &framework.FieldData{Raw: map[string]any{"jwt": mintK8sSAJWT("https://kube", "default", "x")}, Schema: b.pathLogin().Fields}
		resp, err := b.handleLogin(ctx, &logical.Request{}, d)
		require.NoError(t, err)
		require.NotNil(t, resp.Err)
		assert.Contains(t, resp.Err.Error(), "role is required")
	})

	t.Run("role not found", func(t *testing.T) {
		d := &framework.FieldData{Raw: map[string]any{"jwt": mintK8sSAJWT("https://kube", "default", "x"), "role": "ghost"}, Schema: b.pathLogin().Fields}
		resp, err := b.handleLogin(ctx, &logical.Request{}, d)
		require.NoError(t, err)
		require.NotNil(t, resp.Err)
		assert.Contains(t, resp.Err.Error(), "not found")
	})

	t.Run("backend not configured", func(t *testing.T) {
		fresh, freshCtx := newTestBackend(t)
		d := &framework.FieldData{Raw: map[string]any{"jwt": "x", "role": "y"}, Schema: fresh.pathLogin().Fields}
		resp, err := fresh.handleLogin(freshCtx, &logical.Request{}, d)
		require.NoError(t, err)
		require.NotNil(t, resp.Err)
		assert.Contains(t, resp.Err.Error(), "not configured")
	})
}
