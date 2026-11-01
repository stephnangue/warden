package core

import (
	"context"
	"testing"
	"time"

	"github.com/stephnangue/warden/helper/selector"
	"github.com/stephnangue/warden/internal/cachesize"
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

// The cache charges an entry its approximate size: the struct, what its
// strings, policies, data, metadata and actors hold, and the facts its
// admission retains.
func TestEntryCost(t *testing.T) {
	base := tokenEntryStructBytes
	assert.Equal(t, base, entryCost(&TokenEntry{}), "an empty entry")
	assert.Equal(t, base+admissionStructBytes, entryCost(&TokenEntry{Admission: &logical.Admission{}}), "no estimate")
	assert.Equal(t, base+admissionStructBytes+4096, entryCost(&TokenEntry{Admission: &logical.Admission{Bytes: 4096}}))
	assert.Equal(t, base+admissionStructBytes, entryCost(&TokenEntry{Admission: &logical.Admission{Bytes: -1}}))

	full := &TokenEntry{
		ID:             "wds_0123456789", // 14
		Accessor:       "acc",            // 3
		NamespacePath:  "team/",          // 5
		Policies:       []string{"a", "bc"},
		Data:           map[string]string{"k": "vv"},
		Metadata:       map[string]string{"mm": "n"},
		Actors:         []logical.ActorRef{{Subject: "agent", Issuer: "iss"}},
		CredentialSpec: "spec", // 4
	}
	want := base + 14 + 3 + 5 + 4 + (1 + 2) +
		cachesize.StringMapBytes(full.Data) + cachesize.StringMapBytes(full.Metadata) + actorRefBytes + 5 + 3
	assert.Equal(t, want, entryCost(full))

	// The struct sizes are measured, not assumed: within reach of what the
	// structs hold today, so a struct that grows is charged for it.
	assert.InDelta(t, 328, tokenEntryStructBytes, 200)
	assert.InDelta(t, 176, admissionStructBytes, 150)
}

// entryCost runs on every cache insert, lookup misses and ticket decodes
// included, so it allocates nothing.
func TestEntryCost_NoAllocations(t *testing.T) {
	e := &TokenEntry{
		ID: "wds_x", Policies: []string{"p"}, Data: map[string]string{"k": "v"},
		Metadata: map[string]string{"m": "n"}, Actors: []logical.ActorRef{{Subject: "s"}},
		Admission: &logical.Admission{Bytes: 512},
	}
	assert.Zero(t, testing.AllocsPerRun(1000, func() { _ = entryCost(e) }))
}

// Every copy the token store hands out shares the one *Admission of the cached
// entry, so state an admission carries is seen by every request on the token.
func TestTokenStore_AdmissionSharedAcrossTransparentCopies(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	const jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhZ2VudC0xIn0.admission-signature"
	adm := testAdmission()
	created, err := core.tokenStore.GenerateToken(ctx, TypeIdentityToken, &AuthData{
		TokenValue:    jwt,
		MountAccessor: "auth_jwt_1",
		PrincipalID:   "agent-1",
		ExpireAt:      time.Now().Add(time.Hour),
		Admission:     adm,
	})
	require.NoError(t, err)
	require.Same(t, adm, created.Admission)

	first, err := core.LookupTransparentToken(ctx, jwt, "auth_jwt_1")
	require.NoError(t, err)
	second, err := core.LookupTransparentToken(ctx, jwt, "auth_jwt_1")
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
	created, err := core.tokenStore.GenerateToken(ctx, TypeServiceToken, &AuthData{
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
					TokenType:   TypeServiceToken,
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
			core.setAdmissionMount(tc.ctx, tc.req, adm)
			assert.Equal(t, tc.want, adm.MountPath)
		})
	}
}

// aliasAdmission returns an admission of claims from a mount whose naming
// takes the alias from source.
func aliasAdmission(t *testing.T, source string, claims map[string]any) *logical.Admission {
	t.Helper()
	mapping, err := selector.CompileMapping([]string{"sub", "iss", "aud"}, map[string]string{"repository": "repo"})
	require.NoError(t, err)
	naming, err := logical.NewMountNaming(mapping, logical.EntityKindAgent)
	require.NoError(t, err)
	naming.AliasSource = source
	mf := &logical.MountFacts{}
	mf.Publish(naming)
	return &logical.Admission{Facts: selector.NewClaims(claims), Mount: mf}
}

// setAdmissionMount names the admitting mount's accessor and derives the
// alias under the naming in force, on a login as on a discovery admission
// (both complete their admission through it); an alias that cannot be derived
// is left empty and the login still succeeds.
func TestSetAdmissionMount_AccessorAndAlias(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	req := &logical.Request{MountPoint: "auth/jwt/", MountAccessor: "auth_jwt_1"}

	adm := aliasAdmission(t, "sub", map[string]any{"sub": "agent-1"})
	core.setAdmissionMount(ctx, req, adm)
	assert.Equal(t, "auth/jwt/", adm.MountPath)
	assert.Equal(t, "auth_jwt_1", adm.MountAccessor)
	assert.Equal(t, "agent-1", adm.AliasName)

	adm = aliasAdmission(t, "repo", map[string]any{"sub": "x", "repository": "acme/deployer"})
	core.setAdmissionMount(ctx, req, adm)
	assert.Equal(t, "acme/deployer", adm.AliasName, "a mapped fact as the source")

	adm = aliasAdmission(t, "repo", map[string]any{"sub": "x"})
	core.setAdmissionMount(ctx, req, adm)
	assert.Empty(t, adm.AliasName, "an absent source yields no alias")
	assert.Equal(t, "auth_jwt_1", adm.MountAccessor, "the accessor is set regardless")

	adm = aliasAdmission(t, "", map[string]any{"sub": "agent-1"})
	core.setAdmissionMount(ctx, req, adm)
	assert.Empty(t, adm.AliasName, "a mount naming no source")

	// A login whose credential yields no alias still issues its token.
	adm = aliasAdmission(t, "sub", map[string]any{"sub": map[string]any{"nested": true}})
	resp := &logical.Response{
		Data: map[string]any{},
		Auth: &logical.Auth{TokenType: TypeServiceToken, PrincipalID: "p", Policies: []string{"default"},
			TokenTTL: time.Hour, Admission: adm},
	}
	_, err := core.LoginCreateToken(ctx, &logical.Request{MountPoint: "auth/jwt/", MountAccessor: "auth_jwt_1"}, resp)
	require.NoError(t, err)
	assert.Empty(t, adm.AliasName)
	entry, found := core.tokenStore.byID.Get(resp.Data["token_id"].(string))
	require.True(t, found)
	assert.Same(t, adm, entry.Admission)

	// An admission already completed is kept as it is.
	adm = aliasAdmission(t, "sub", map[string]any{"sub": "agent-1"})
	adm.AliasName = "preset"
	core.setAdmissionMount(ctx, req, adm)
	assert.Equal(t, "preset", adm.AliasName)
	assert.Empty(t, adm.MountAccessor)
}

// A login without an admission issues a token without one.
func TestLoginCreateToken_NoAdmission(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	resp := &logical.Response{
		Data: map[string]any{},
		Auth: &logical.Auth{TokenType: TypeServiceToken, Policies: []string{"default"}, TokenTTL: time.Hour},
	}
	_, err := core.LoginCreateToken(ctx, &logical.Request{MountPoint: "auth/jwt/"}, resp)
	require.NoError(t, err)
	entry, found := core.tokenStore.byID.Get(resp.Data["token_id"].(string))
	require.True(t, found)
	assert.Nil(t, entry.Admission)
}

// The login response names the issued token's type as it is, with no alias:
// identity_token for a transparent login, service_token otherwise.
func TestLoginCreateToken_TokenType(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	login := func(auth *logical.Auth) map[string]any {
		t.Helper()
		resp := &logical.Response{Data: map[string]any{}, Auth: auth}
		_, err := core.LoginCreateToken(ctx, &logical.Request{MountPoint: "auth/jwt/", MountAccessor: "auth_jwt_1"}, resp)
		require.NoError(t, err)
		return resp.Data
	}

	identity := login(&logical.Auth{
		TokenType: TypeIdentityToken, PrincipalID: "agent-1", TokenTTL: time.Hour,
		ClientToken: "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhZ2VudC0xIn0.sig", Admission: testAdmission(),
	})
	assert.Equal(t, "identity_token", identity["token_type"])
	assert.Regexp(t, `^wdi_[0-9a-f]{32}$`, identity["token_id"])
	assert.NotContains(t, identity["data"], "token", "no value is handed out for an identity token")

	service := login(&logical.Auth{TokenType: TypeServiceToken, Policies: []string{"default"}, TokenTTL: time.Hour})
	assert.Equal(t, "service_token", service["token_type"])
	assert.Regexp(t, `^wds_[0-9a-f]{32}$`, service["token_id"])
	assert.Regexp(t, `^wds\.`, service["data"].(map[string]string)["token"])
}
