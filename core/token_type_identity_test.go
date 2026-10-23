package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const identityTestJWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzcGlmZmU6Ly9leGFtcGxlLm9yZy9hcGkifQ.sig"

func TestIdentityTokenType_Metadata(t *testing.T) {
	meta := identityTokenType.Metadata()
	assert.Equal(t, "identity_token", meta.Name)
	assert.Equal(t, TypeIdentityToken, meta.Name)
	assert.Equal(t, "wdi_", meta.IDPrefix)
	assert.Empty(t, meta.ValuePrefix, "an identity token has no value to detect")
	assert.Empty(t, meta.LegacyValuePrefix)
	assert.True(t, identityTokenType.IsTransparent())
	assert.Equal(t, "credential", identityTokenType.LookupKey())
	assert.True(t, identityTokenType.ValidateValue(""), "no bearer value to validate")
}

// The stored value is the hash of (mount accessor, credential), never the raw
// credential, and the ID is wdi_ followed by the 32-hex hash of that.
func TestIdentityTokenType_GenerateAndID(t *testing.T) {
	entry := &TokenEntry{Data: map[string]string{}}
	_, err := identityTokenType.Generate(context.Background(), &AuthData{TokenValue: identityTestJWT, MountAccessor: "acc1"}, entry)
	require.NoError(t, err)

	want := sha256.Sum256([]byte("acc1:" + identityTestJWT))
	assert.Equal(t, hex.EncodeToString(want[:]), entry.Data["credential"])
	assert.Len(t, entry.Data, 1, "one data key whatever the auth method")

	id := identityTokenType.ComputeID(entry.Data["credential"])
	assert.Regexp(t, `^wdi_[0-9a-f]{32}$`, id)
	assert.Equal(t, id, identityTokenType.ComputeID(identityTokenType.LookupValue(identityTestJWT, "acc1")),
		"creation and lookup compute the same ID")

	for name, authData := range map[string]*AuthData{"nil": nil, "empty credential": {MountAccessor: "acc1"}} {
		t.Run(name, func(t *testing.T) {
			e := &TokenEntry{Data: map[string]string{"kept": "x"}}
			out, err := identityTokenType.Generate(context.Background(), authData, e)
			require.NoError(t, err)
			assert.Equal(t, map[string]string{"kept": "x"}, out)
		})
	}
}

// The mount accessor keys the cache: one credential at two mounts is two
// entries, and a spiffe mount's certificate fingerprint and JWT-SVID never meet.
func TestIdentityTokenType_LookupValue(t *testing.T) {
	h := identityTokenType.LookupValue
	assert.Equal(t, h(identityTestJWT, "acc1"), h(identityTestJWT, "acc1"))
	assert.NotEqual(t, h(identityTestJWT, "accA"), h(identityTestJWT, "accB"))
	fingerprint := strings.Repeat("ab", 32)
	assert.NotEqual(t, h(fingerprint, "acc1"), h(identityTestJWT, "acc1"))
}

func TestIdentityTokenType_Registry(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	assert.ElementsMatch(t, []string{"identity_token", "service_token"}, core.tokenStore.ListTokenTypes())
	assert.True(t, core.tokenStore.IsTransparentType("identity_token"))
	assert.False(t, core.tokenStore.IsTransparentType("service_token"))
	assert.False(t, core.tokenStore.IsTransparentType("warden_token"), "a type stored by an earlier release stays persisted")
	for _, old := range []string{"jwt_role", "cert_role", "kubernetes_role", "spiffe_role"} {
		assert.False(t, core.tokenStore.IsTransparentType(old), old)
		_, err := core.tokenStore.registry.GetByName(old)
		assert.ErrorIs(t, err, ErrTypeNotFound, old)
	}
	_, err := core.tokenStore.registry.DetectType(identityTestJWT)
	assert.ErrorIs(t, err, ErrTypeNotFound, "a JWT is no token type's value")
}

// Every transparent auth method issues the one identity token type, one cache
// entry per (mount, credential): the same JWT at a jwt, a kubernetes and a
// spiffe mount is three entries, each resolved at its own mount only.
func TestIdentityToken_OneTypeForAllMethods(t *testing.T) {
	core := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	jwt := mintK8sJWT(`{"sub":"spiffe://example.org/ns/default/sa/api"}`)
	cert, fingerprint := spiffeFakeCert("one-type-cert")

	type method struct {
		typ, path, credential string
		req                   func() *logical.Request
	}
	methods := []method{
		{"jwt", "jwt-one/", jwt, func() *logical.Request { return &logical.Request{ClientToken: jwt} }},
		{"kubernetes", "k8s-one/", jwt, func() *logical.Request { return &logical.Request{ClientToken: jwt} }},
		{"spiffe", "spiffe-one/", jwt, func() *logical.Request { return &logical.Request{ClientToken: jwt} }},
		{"cert", "cert-one/", fingerprint, func() *logical.Request { return spiffeReqWithCert(cert, "") }},
	}

	ids := map[string]string{}
	for _, m := range methods {
		mount := mountStubAuthMethod(t, core, m.path, m.typ)
		te, err := core.tokenStore.GenerateToken(ctx, TypeIdentityToken, &AuthData{
			TokenValue: m.credential, MountAccessor: mount.Accessor,
			PrincipalID: "agent-" + m.typ, ExpireAt: time.Now().Add(time.Hour),
		})
		require.NoError(t, err, m.typ)
		assert.Equal(t, "identity_token", te.Type, m.typ)
		assert.Regexp(t, `^wdi_[0-9a-f]{32}$`, te.ID, m.typ)
		ids[m.typ] = te.ID
	}
	assert.Len(t, map[string]bool{ids["jwt"]: true, ids["kubernetes"]: true, ids["spiffe"]: true, ids["cert"]: true}, 4,
		"one entry per (mount, credential): the same JWT at three mounts does not collide")

	for _, m := range methods {
		provider := &mockTransparentModeProvider{transparentMode: true, autoAuthPath: "auth/" + m.path}
		req := m.req()
		require.NoError(t, core.handleTransparentAuth(ctx, req, provider, "api"), m.typ)
		require.NotNil(t, req.TokenEntry(), m.typ)
		assert.Equal(t, ids[m.typ], req.TokenEntry().ID, "%s resolves its own mount's entry", m.typ)
		assert.Equal(t, "agent-"+m.typ, req.TokenEntry().PrincipalID, m.typ)
	}
}

// The resolver takes the credential where the mount's auth method says it is:
// a bearer JWT for jwt and kubernetes, a client certificate for cert, either
// SVID for spiffe; a mount whose backend names no format is refused.
func TestIdentityToken_CredentialFormatDispatch(t *testing.T) {
	core := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	for _, typ := range []string{"jwt", "kubernetes", "cert", "spiffe"} {
		mountStubAuthMethod(t, core, typ+"-fmt/", typ)
	}
	mountStubAuthMethod(t, core, "other-fmt/", "other")
	cert, _ := spiffeFakeCert("dispatch-cert")

	cases := []struct {
		name, mount string
		req         *logical.Request
		wantErr     string
	}{
		{"jwt wants a bearer JWT", "jwt-fmt/", spiffeReqWithCert(cert, ""), "requires a JWT bearer token"},
		{"kubernetes wants a bearer JWT", "kubernetes-fmt/", spiffeReqWithCert(cert, ""), "requires a JWT bearer token"},
		{"cert wants a client certificate", "cert-fmt/", &logical.Request{ClientToken: identityTestJWT}, "requires a TLS client certificate"},
		{"spiffe wants an SVID", "spiffe-fmt/", &logical.Request{}, "requires an X.509-SVID (TLS/forwarded cert) or a JWT-SVID"},
		{"no credential format", "other-fmt/", &logical.Request{ClientToken: identityTestJWT}, `auth method "other" at "auth/other-fmt/" does not support implicit auth`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			provider := &mockTransparentModeProvider{transparentMode: true, autoAuthPath: "auth/" + tc.mount}
			err := core.handleTransparentAuth(ctx, tc.req, provider, "api")
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}

	// The format reaches the dispatch through the backend the router returns
	// with the mount: one lookup for both.
	entry, backend := core.router.MatchingMountEntryAndBackend(ctx, "auth/cert-fmt/")
	require.NotNil(t, entry)
	provider, ok := backend.(logical.CredentialFormatProvider)
	require.True(t, ok)
	assert.Equal(t, logical.CredentialFormatCert, provider.CredentialFormat())
	entry, backend = core.router.MatchingMountEntryAndBackend(ctx, "auth/never-mounted/")
	assert.Nil(t, entry)
	assert.Nil(t, backend)
}
