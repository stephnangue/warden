package core

import (
	"context"
	"testing"
	"time"

	"github.com/stephnangue/warden/helper/selector"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testAdmission() *logical.Admission {
	return &logical.Admission{
		Facts: selector.NewClaims(map[string]any{"sub": "agent-1"}),
		Mount: &logical.MountFacts{},
	}
}

// The cache counts the facts an admission retains in the cost of its entry.
func TestEntryCost(t *testing.T) {
	assert.Equal(t, baseEntryCost, entryCost(&TokenEntry{}), "no admission")
	assert.Equal(t, baseEntryCost, entryCost(&TokenEntry{Admission: &logical.Admission{}}), "no estimate")
	assert.Equal(t, baseEntryCost+4096, entryCost(&TokenEntry{Admission: &logical.Admission{Bytes: 4096}}))
	assert.Equal(t, baseEntryCost, entryCost(&TokenEntry{Admission: &logical.Admission{Bytes: -1}}))
}

// Every copy the token store hands out shares the one *Admission of the cached
// entry, so state an admission carries is seen by every request on the token.
func TestTokenStore_AdmissionSharedAcrossTransparentCopies(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	const jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhZ2VudC0xIn0.admission-signature"
	adm := testAdmission()
	created, err := core.tokenStore.GenerateToken(ctx, TypeJWTRole, &AuthData{
		TokenValue:    jwt,
		MountAccessor: "auth_jwt_1",
		RoleName:      "reader",
		PrincipalID:   "agent-1",
		ExpireAt:      time.Now().Add(time.Hour),
		Admission:     adm,
	})
	require.NoError(t, err)
	require.Same(t, adm, created.Admission)

	jwtType := &JWTRoleTokenType{}
	first, err := core.LookupTransparentTokenWithRole(ctx, jwtType, jwt, "auth_jwt_1", "reader")
	require.NoError(t, err)
	second, err := core.LookupTransparentTokenWithRole(ctx, jwtType, jwt, "auth_jwt_1", "reader")
	require.NoError(t, err)

	assert.NotSame(t, first, second, "each lookup returns its own copy")
	assert.NotSame(t, created, first)
	assert.Same(t, adm, first.Admission)
	assert.Same(t, adm, second.Admission)
}

func TestTokenStore_AdmissionSharedAcrossAccessorLookups(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	adm := testAdmission()
	created, err := core.tokenStore.GenerateToken(ctx, TypeWardenToken, &AuthData{
		PrincipalID: "agent-1",
		ExpireAt:    time.Now().Add(time.Hour),
		Policies:    []string{"default"},
		Admission:   adm,
	})
	require.NoError(t, err)

	byAccessor, err := core.tokenStore.LookupByAccessor(ctx, created.Accessor)
	require.NoError(t, err)
	assert.NotSame(t, created, byAccessor)
	assert.Same(t, adm, byAccessor.Admission)
}

func TestTokenStore_ReplaceRootTokenValueCarriesAdmission(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	_, err := core.tokenStore.GenerateRootToken()
	require.NoError(t, err)
	root, found := core.tokenStore.byID.Get(core.tokenStore.rootTokenManager.GetCurrentRootTokenID())
	require.True(t, found)
	adm := testAdmission()
	root.Admission = adm // no root token carries one; set to see the copy

	require.NoError(t, core.tokenStore.ReplaceRootTokenValue("my-dev-token"))

	entry, err := core.LookupToken(ctx, "my-dev-token")
	require.NoError(t, err)
	assert.Same(t, adm, entry.Admission)
}

// LoginCreateToken names the admission's mount relative to the namespace and
// carries the admission onto the issued token.
func TestLoginCreateToken_AdmissionMountPath(t *testing.T) {
	child := &namespace.Namespace{ID: "ns1id", UUID: "ns1-uuid", Path: "ns1/"}
	cases := []struct {
		name       string
		ns         *namespace.Namespace
		mountPoint string
	}{
		{"root namespace", namespace.RootNamespace, "auth/jwt/"},
		{"child namespace", child, "ns1/auth/jwt/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			core := createTestCore(t)
			defer core.tokenStore.Close()
			ctx := namespace.ContextWithNamespace(context.Background(), tc.ns)

			adm := testAdmission()
			resp := &logical.Response{
				Data: map[string]any{},
				Auth: &logical.Auth{
					TokenType:   TypeWardenToken,
					PrincipalID: "agent-1",
					Policies:    []string{"default"},
					TokenTTL:    time.Hour,
					Admission:   adm,
				},
			}
			req := &logical.Request{MountPoint: tc.mountPoint, MountAccessor: "auth_jwt_1"}
			_, err := core.LoginCreateToken(ctx, req, resp)
			require.NoError(t, err)

			assert.Equal(t, "auth/jwt/", adm.MountPath)
			entry, found := core.tokenStore.byID.Get(resp.Data["token_id"].(string))
			require.True(t, found)
			assert.Same(t, adm, entry.Admission)
		})
	}
}

// A mount that cannot be named relative to the namespace leaves MountPath
// empty (the "mount" fact absent), and a MountPath already set is kept.
func TestSetAdmissionMountPath(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()
	child := &namespace.Namespace{ID: "ns1id", UUID: "ns1-uuid", Path: "ns1/"}
	inChild := namespace.ContextWithNamespace(context.Background(), child)
	inRoot := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	cases := []struct {
		name   string
		ctx    context.Context
		req    *logical.Request
		preset string
		want   string
	}{
		{"root", inRoot, &logical.Request{MountPoint: "auth/jwt/"}, "", "auth/jwt/"},
		{"child", inChild, &logical.Request{MountPoint: "ns1/auth/jwt/"}, "", "auth/jwt/"},
		{"outside the namespace", inChild, &logical.Request{MountPoint: "ns2/auth/jwt/"}, "", ""},
		{"namespace itself", inChild, &logical.Request{MountPoint: "ns1/"}, "", ""},
		{"no request", inRoot, nil, "", ""},
		{"no namespace", context.Background(), &logical.Request{MountPoint: "auth/jwt/"}, "", ""},
		{"already set", inRoot, &logical.Request{MountPoint: "auth/other/"}, "auth/jwt/", "auth/jwt/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			adm := &logical.Admission{MountPath: tc.preset}
			core.setAdmissionMountPath(tc.ctx, tc.req, adm)
			assert.Equal(t, tc.want, adm.MountPath)
		})
	}
}

// A login without an admission issues a token without one.
func TestLoginCreateToken_NoAdmission(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	resp := &logical.Response{
		Data: map[string]any{},
		Auth: &logical.Auth{TokenType: TypeWardenToken, Policies: []string{"default"}, TokenTTL: time.Hour},
	}
	_, err := core.LoginCreateToken(ctx, &logical.Request{MountPoint: "auth/jwt/"}, resp)
	require.NoError(t, err)
	entry, found := core.tokenStore.byID.Get(resp.Data["token_id"].(string))
	require.True(t, found)
	assert.Nil(t, entry.Admission)
}
