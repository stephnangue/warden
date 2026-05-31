package kubernetes

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

// introspectRequest builds a logical.Request carrying the JWT in the
// Authorization header — the path the production aggregator uses.
func introspectRequest(t *testing.T, jwt string) *logical.Request {
	t.Helper()
	httpReq := httptest.NewRequest(http.MethodGet, "/v1/auth/kubernetes/introspect/roles", nil)
	httpReq.Header.Set("Authorization", "Bearer "+jwt)
	return &logical.Request{
		Operation:   logical.ReadOperation,
		Path:        "introspect/roles",
		HTTPRequest: httpReq,
	}
}

// introspectSetup builds a backend wired to a fake apiserver and seeds
// the roles the aggregator should pick from.
func introspectSetup(t *testing.T, status tokenReviewStatus) (*kubernetesAuthBackend, *fakeAPIServer) {
	t.Helper()
	b, ctx := newTestBackend(t)
	fake := newFakeAPIServer(t, fakeAPIServerOpts{Response: status})
	require.NoError(t, b.setupConfig(ctx, map[string]any{
		"kubernetes_host": fake.URL,
		"tls_skip_verify": true,
	}))
	return b, fake
}

func TestIntrospect_ReturnsEmptyWhenNoJWT(t *testing.T) {
	b, _ := introspectSetup(t, tokenReviewStatus{Authenticated: true})
	resp, err := b.handleIntrospectRoles(t.Context(), &logical.Request{}, &framework.FieldData{})
	require.NoError(t, err)
	require.NotNil(t, resp)
	roles := resp.Data["roles"].([]introspectedRole)
	assert.Empty(t, roles, "missing JWT should produce empty list, not an error")
}

func TestIntrospect_ReturnsEmptyWhenBackendNotConfigured(t *testing.T) {
	b, _ := newTestBackend(t)
	jwt := mintK8sSAJWT("https://kube", "default", "myapp")
	resp, err := b.handleIntrospectRoles(t.Context(), introspectRequest(t, jwt), &framework.FieldData{})
	require.NoError(t, err)
	roles := resp.Data["roles"].([]introspectedRole)
	assert.Empty(t, roles)
}

func TestIntrospect_ReturnsEmptyOnTokenReviewDenial(t *testing.T) {
	b, _ := introspectSetup(t, tokenReviewStatus{
		Authenticated: false,
		Error:         "token rejected",
	})
	jwt := mintK8sSAJWT("https://kube", "default", "myapp")
	resp, err := b.handleIntrospectRoles(t.Context(), introspectRequest(t, jwt), &framework.FieldData{})
	require.NoError(t, err)
	roles := resp.Data["roles"].([]introspectedRole)
	assert.Empty(t, roles)
}

func TestIntrospect_OnlyOneTokenReviewRegardlessOfRoleCount(t *testing.T) {
	b, fake := introspectSetup(t, tokenReviewStatus{
		Authenticated: true,
		User:          tokenReviewUser{Username: "system:serviceaccount:default:myapp"},
		Audiences:     []string{"https://kubernetes.default.svc"},
	})
	ctx := t.Context()

	// Seed 5 roles, all matching the same SA. The design pins one
	// TokenReview call total, not one per role — that's the whole
	// point of the introspect design constraint.
	for _, name := range []string{"r1", "r2", "r3", "r4", "r5"} {
		_, _ = b.handleRoleCreate(ctx, nil, roleFieldData(t, b, map[string]any{
			"name":                             name,
			"bound_service_account_names":      []string{"myapp"},
			"bound_service_account_namespaces": []string{"default"},
		}))
	}

	jwt := mintK8sSAJWT("https://kube", "default", "myapp")
	resp, err := b.handleIntrospectRoles(ctx, introspectRequest(t, jwt), &framework.FieldData{})
	require.NoError(t, err)
	roles := resp.Data["roles"].([]introspectedRole)
	assert.Len(t, roles, 5)
	assert.Equal(t, int32(1), fake.Calls,
		"introspect must make exactly ONE TokenReview call regardless of role count")
}

func TestIntrospect_TokenReviewSentWithoutAudienceBinding(t *testing.T) {
	b, fake := introspectSetup(t, tokenReviewStatus{
		Authenticated: true,
		User:          tokenReviewUser{Username: "system:serviceaccount:default:myapp"},
		Audiences:     []string{"https://kubernetes.default.svc"},
	})
	jwt := mintK8sSAJWT("https://kube", "default", "myapp")
	_, _ = b.handleIntrospectRoles(t.Context(), introspectRequest(t, jwt), &framework.FieldData{})

	// Introspect must NOT request a specific audience — the trade-off
	// is that we learn the token's natural audiences instead, and filter
	// per-role locally.
	assert.Empty(t, fake.AudsSeen,
		"introspect must call TokenReview without audience binding")
}

func TestIntrospect_FiltersByRoleSABindings(t *testing.T) {
	b, _ := introspectSetup(t, tokenReviewStatus{
		Authenticated: true,
		User:          tokenReviewUser{Username: "system:serviceaccount:default:myapp"},
	})
	ctx := t.Context()

	// myapp role matches; other-app role doesn't.
	_, _ = b.handleRoleCreate(ctx, nil, roleFieldData(t, b, map[string]any{
		"name":                             "myapp-role",
		"bound_service_account_names":      []string{"myapp"},
		"bound_service_account_namespaces": []string{"default"},
	}))
	_, _ = b.handleRoleCreate(ctx, nil, roleFieldData(t, b, map[string]any{
		"name":                             "other-role",
		"bound_service_account_names":      []string{"other-app"},
		"bound_service_account_namespaces": []string{"default"},
	}))

	jwt := mintK8sSAJWT("https://kube", "default", "myapp")
	resp, err := b.handleIntrospectRoles(ctx, introspectRequest(t, jwt), &framework.FieldData{})
	require.NoError(t, err)
	roles := resp.Data["roles"].([]introspectedRole)
	require.Len(t, roles, 1)
	assert.Equal(t, "myapp-role", roles[0].Name)
}

func TestIntrospect_FiltersByAudience(t *testing.T) {
	b, _ := introspectSetup(t, tokenReviewStatus{
		Authenticated: true,
		User:          tokenReviewUser{Username: "system:serviceaccount:default:myapp"},
		Audiences:     []string{"https://allowed-aud", "https://kubernetes.default.svc"},
	})
	ctx := t.Context()

	// Role pinned to an audience the token DOES have → included.
	_, _ = b.handleRoleCreate(ctx, nil, roleFieldData(t, b, map[string]any{
		"name":                             "allowed",
		"bound_service_account_names":      []string{"myapp"},
		"bound_service_account_namespaces": []string{"default"},
		"audience":                         "https://allowed-aud",
	}))
	// Role pinned to an audience the token does NOT have → excluded.
	_, _ = b.handleRoleCreate(ctx, nil, roleFieldData(t, b, map[string]any{
		"name":                             "forbidden",
		"bound_service_account_names":      []string{"myapp"},
		"bound_service_account_namespaces": []string{"default"},
		"audience":                         "https://other-aud",
	}))
	// Role with no audience binding → included regardless.
	_, _ = b.handleRoleCreate(ctx, nil, roleFieldData(t, b, map[string]any{
		"name":                             "unbound",
		"bound_service_account_names":      []string{"myapp"},
		"bound_service_account_namespaces": []string{"default"},
	}))

	jwt := mintK8sSAJWT("https://kube", "default", "myapp")
	resp, err := b.handleIntrospectRoles(ctx, introspectRequest(t, jwt), &framework.FieldData{})
	require.NoError(t, err)
	roles := resp.Data["roles"].([]introspectedRole)
	names := make([]string, 0, len(roles))
	for _, r := range roles {
		names = append(names, r.Name)
	}
	assert.ElementsMatch(t, []string{"allowed", "unbound"}, names,
		"only roles whose audience binding is satisfied (or unbound) should appear")
}

func TestIntrospect_IssuerPinShortCircuitsBeforeTokenReview(t *testing.T) {
	b, ctx := newTestBackend(t)
	fake := newFakeAPIServer(t, fakeAPIServerOpts{
		Response: tokenReviewStatus{Authenticated: true},
	})
	require.NoError(t, b.setupConfig(ctx, map[string]any{
		"kubernetes_host": fake.URL,
		"tls_skip_verify": true,
		"issuer":          "https://cluster-a.svc",
	}))

	// Token from wrong cluster.
	jwt := mintK8sSAJWT("https://cluster-b.svc", "default", "myapp")
	resp, err := b.handleIntrospectRoles(ctx, introspectRequest(t, jwt), &framework.FieldData{})
	require.NoError(t, err)
	roles := resp.Data["roles"].([]introspectedRole)
	assert.Empty(t, roles)
	assert.Equal(t, int32(0), fake.Calls,
		"issuer pin must reject before the TokenReview round-trip")
}

func TestIntrospect_AcceptsJWTFromReqClientToken(t *testing.T) {
	// In-process callers (the sys/introspect/roles aggregator) stash the
	// JWT on req.ClientToken instead of the Authorization header.
	b, _ := introspectSetup(t, tokenReviewStatus{
		Authenticated: true,
		User:          tokenReviewUser{Username: "system:serviceaccount:default:myapp"},
	})
	_, _ = b.handleRoleCreate(t.Context(), nil, roleFieldData(t, b, map[string]any{
		"name":                             "viaclient",
		"bound_service_account_names":      []string{"myapp"},
		"bound_service_account_namespaces": []string{"default"},
	}))

	jwt := mintK8sSAJWT("https://kube", "default", "myapp")
	req := &logical.Request{
		Operation:   logical.ReadOperation,
		Path:        "introspect/roles",
		ClientToken: jwt,
	}
	resp, err := b.handleIntrospectRoles(t.Context(), req, &framework.FieldData{})
	require.NoError(t, err)
	roles := resp.Data["roles"].([]introspectedRole)
	assert.Len(t, roles, 1)
}
