package core

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/listener"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockUserAuthProvider extends the transparent-mode mock with the secondary
// (user) auth config, so captureUserContext / resolveUserAuthConfig can read
// user_auth_path etc. off the backend via logical.UserAuthConfigProvider.
type mockUserAuthProvider struct {
	mockTransparentModeProvider
	userAuthPath    string
	userTokenHeader string
	userAuthRole    string
}

func (m *mockUserAuthProvider) GetUserAuthPath() string    { return m.userAuthPath }
func (m *mockUserAuthProvider) GetUserTokenHeader() string { return m.userTokenHeader }
func (m *mockUserAuthProvider) GetUserAuthRole() string    { return m.userAuthRole }

// seedUserToken caches a transparent JWT-role token on the given mount so a later
// resolveTransparentIdentity call resolves it from cache without a login.
func seedUserToken(t *testing.T, core *Core, ctx context.Context, mount *MountEntry, jwt, role, principal string) *TokenEntry {
	t.Helper()
	te, err := core.tokenStore.GenerateToken(ctx, TypeJWTRole, &AuthData{
		TokenValue:    jwt,
		MountAccessor: mount.Accessor,
		RoleName:      role,
		PrincipalID:   principal,
		ExpireAt:      time.Now().Add(time.Hour),
		Policies:      []string{"default"},
	})
	require.NoError(t, err)
	return te
}

// TestResolveTransparentIdentity_NoRequestMutation asserts the factored resolver
// performs NONE of performImplicitAuth's request mutations: it must not set
// req.Transparent, must not write req.ClientToken, and must not set the primary
// token entry. Those belong to the primary principal alone — leaking any would
// promote the secondary (user) principal to primary.
func TestResolveTransparentIdentity_NoRequestMutation(t *testing.T) {
	core := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	mount := mountStubAuthMethod(t, core, "user-jwt/", "jwt")
	userJWT := mintK8sJWT(`{"sub":"alice"}`)
	userTE := seedUserToken(t, core, ctx, mount, userJWT, "slack-user", "alice")

	const agentToken = "agent-primary-token" // opaque; resolver never reads it
	req := &logical.Request{
		ClientToken: agentToken,
		HTTPRequest: httptest.NewRequest(http.MethodPost, "/v1/slack-mcp/role/agent/gateway", nil),
	}

	te, clearClientToken, err := core.resolveTransparentIdentity(ctx, req, "auth/user-jwt/", "slack-user", userJWT)
	require.NoError(t, err)
	require.NotNil(t, te)
	assert.Equal(t, userTE.ID, te.ID)
	assert.False(t, clearClientToken, "the JWT path never signals a ClientToken clear")

	// No request mutation.
	assert.Nil(t, req.TokenEntry(), "must not set the primary token entry")
	assert.False(t, req.Transparent, "must not mark the request transparent")
	assert.Equal(t, agentToken, req.ClientToken, "must not overwrite the agent ClientToken")
	assert.Nil(t, req.User, "resolveTransparentIdentity does not attach req.User")
}

// TestPerformImplicitAuth_CertClearsStrayBearer asserts a cert-authenticated
// primary principal ends up with its cert-minted token ID in ClientToken even when
// the request also carries a stray Authorization bearer (e.g. a secondary user
// token). Without the clear, that bearer would pollute ClientToken and, among
// other things, false-trip the secondary-user "must differ from the agent
// credential" guard for the documented Authorization opt-in.
func TestPerformImplicitAuth_CertClearsStrayBearer(t *testing.T) {
	core := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	mount := mountStubAuthMethod(t, core, "cert/", "cert")
	cert, fingerprint := spiffeFakeCert("agent-cert-der")
	te, err := core.tokenStore.GenerateToken(ctx, TypeCertRole, &AuthData{
		TokenValue:    fingerprint,
		MountAccessor: mount.Accessor,
		RoleName:      "agent",
		PrincipalID:   "cn=agent",
		ExpireAt:      time.Now().Add(time.Hour),
	})
	require.NoError(t, err)

	httpReq := httptest.NewRequest(http.MethodPost, "/v1/vault/role/agent/gateway", nil)
	httpReq = httpReq.WithContext(listener.WithForwardedClientCert(httpReq.Context(), cert))
	strayBearer := mintK8sJWT(`{"sub":"stray-user-token"}`)
	req := &logical.Request{HTTPRequest: httpReq, ClientToken: strayBearer}

	backend := &mockTransparentModeProvider{transparentMode: true, autoAuthPath: "auth/cert/"}
	require.NoError(t, core.handleTransparentAuth(ctx, req, backend, "agent"))
	require.NotNil(t, req.TokenEntry())
	assert.Equal(t, te.ID, req.TokenEntry().ID)
	assert.Equal(t, te.ID, req.ClientToken, "cert auth must set ClientToken to the token ID, not the stray bearer")
}

// TestCaptureUserContext exercises the secondary-user capture fail-closed matrix
// and the identity-only guarantee.
func TestCaptureUserContext(t *testing.T) {
	core := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	userMount := mountStubAuthMethod(t, core, "user-jwt/", "jwt")
	userJWT := mintK8sJWT(`{"sub":"alice"}`)
	userTE := seedUserToken(t, core, ctx, userMount, userJWT, "slack-user", "alice")

	newReq := func(agentToken string, headers map[string]string) *logical.Request {
		hr := httptest.NewRequest(http.MethodPost, "/v1/slack-mcp/role/agent/gateway", nil)
		for k, v := range headers {
			hr.Header.Set(k, v)
		}
		return &logical.Request{ClientToken: agentToken, HTTPRequest: hr}
	}

	t.Run("feature off when no user_auth_path", func(t *testing.T) {
		backend := &mockUserAuthProvider{} // userAuthPath empty
		req := newReq("agent-tok", map[string]string{"X-Warden-User-Token": userJWT})
		require.NoError(t, core.captureUserContext(ctx, req, backend))
		assert.Nil(t, req.User, "unconfigured feature is a no-op")
	})

	t.Run("absent user credential is not an error", func(t *testing.T) {
		backend := &mockUserAuthProvider{userAuthPath: "auth/user-jwt/"}
		req := newReq("agent-tok", nil) // no user header
		require.NoError(t, core.captureUserContext(ctx, req, backend))
		assert.Nil(t, req.User, "no user credential → req.User stays nil, no error")
	})

	t.Run("valid user credential attaches req.User (identity only)", func(t *testing.T) {
		backend := &mockUserAuthProvider{userAuthPath: "auth/user-jwt/", userAuthRole: "slack-user"}
		req := newReq("agent-primary-token", map[string]string{"X-Warden-User-Token": userJWT})
		require.NoError(t, core.captureUserContext(ctx, req, backend))
		require.NotNil(t, req.User)
		assert.Equal(t, userTE.ID, req.User.TokenEntry.ID)
		assert.Equal(t, userJWT, req.User.RawToken)
		// Identity-only: the primary principal is untouched.
		assert.Nil(t, req.TokenEntry(), "user capture must not set the primary token entry")
		assert.False(t, req.Transparent)
		assert.Equal(t, "agent-primary-token", req.ClientToken)
		// The raw user credential is scrubbed from the request so it can't proxy
		// upstream or land in an audit header copy (req.User.RawToken retains it).
		assert.Empty(t, req.HTTPRequest.Header.Get("X-Warden-User-Token"), "user header must be stripped after capture")
	})

	t.Run("custom user_token_header is scrubbed after capture", func(t *testing.T) {
		backend := &mockUserAuthProvider{userAuthPath: "auth/user-jwt/", userTokenHeader: "X-User-Jwt", userAuthRole: "slack-user"}
		req := newReq("agent-primary-token", map[string]string{"X-User-Jwt": userJWT})
		require.NoError(t, core.captureUserContext(ctx, req, backend))
		require.NotNil(t, req.User)
		assert.Empty(t, req.HTTPRequest.Header.Get("X-User-Jwt"), "a custom user header the static strip lists cannot name must still be scrubbed")
	})

	t.Run("Authorization user header for a cert-authenticated agent", func(t *testing.T) {
		// A cert agent's ClientToken is its token ID (not a bearer), so the user
		// token riding Authorization does NOT trip the user==agent guard. This is
		// the documented cert/SPIFFE opt-in; it only works because the primary cert
		// path clears any stray Authorization bearer (see the cert dispatch).
		backend := &mockUserAuthProvider{userAuthPath: "auth/user-jwt/", userTokenHeader: "Authorization", userAuthRole: "slack-user"}
		req := newReq("agent-cert-token-id", map[string]string{"Authorization": "Bearer " + userJWT})
		require.NoError(t, core.captureUserContext(ctx, req, backend))
		require.NotNil(t, req.User)
		assert.Equal(t, userTE.ID, req.User.TokenEntry.ID)
		assert.Empty(t, req.HTTPRequest.Header.Get("Authorization"), "Authorization user header is scrubbed after capture")
	})

	t.Run("namespace-metadata config drives capture", func(t *testing.T) {
		nsWithMeta := &namespace.Namespace{
			ID:   namespace.RootNamespaceID,
			Path: namespace.RootNamespace.Path,
			CustomMetadata: map[string]string{
				"user_auth_path": "auth/user-jwt/",
				"user_auth_role": "slack-user",
			},
		}
		nsCtx := namespace.ContextWithNamespace(context.Background(), nsWithMeta)
		// A plain transparent backend that does NOT implement UserAuthConfigProvider,
		// so the config must come from the namespace metadata.
		backend := &mockTransparentModeProvider{}
		req := newReq("agent-primary-token", map[string]string{"X-Warden-User-Token": userJWT})
		require.NoError(t, core.captureUserContext(nsCtx, req, backend))
		require.NotNil(t, req.User)
		assert.Equal(t, userTE.ID, req.User.TokenEntry.ID)
	})

	t.Run("user credential equal to the agent credential fails closed", func(t *testing.T) {
		backend := &mockUserAuthProvider{userAuthPath: "auth/user-jwt/"}
		req := newReq(userJWT, map[string]string{"X-Warden-User-Token": userJWT})
		err := core.captureUserContext(ctx, req, backend)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must differ from the agent credential")
		assert.Nil(t, req.User)
	})

	t.Run("non-bearer user credential fails closed", func(t *testing.T) {
		backend := &mockUserAuthProvider{userAuthPath: "auth/user-jwt/"}
		req := newReq("agent-tok", map[string]string{"X-Warden-User-Token": "not-a-jwt"})
		err := core.captureUserContext(ctx, req, backend)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "user authentication failed")
		assert.Nil(t, req.User)
	})

	t.Run("cert-format user mount rejected (bearer required)", func(t *testing.T) {
		mountStubAuthMethod(t, core, "user-cert/", "cert")
		backend := &mockUserAuthProvider{userAuthPath: "auth/user-cert/"}
		req := newReq("agent-tok", map[string]string{"X-Warden-User-Token": userJWT})
		err := core.captureUserContext(ctx, req, backend)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "bearer credential")
		assert.Nil(t, req.User)
	})
}

// TestResolveUserAuthConfig covers the provider-then-namespace precedence for the
// secondary-user auth configuration.
func TestResolveUserAuthConfig(t *testing.T) {
	core := createTestCore(t)

	t.Run("provider config wins", func(t *testing.T) {
		ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
		backend := &mockUserAuthProvider{userAuthPath: "auth/prov/", userTokenHeader: "X-Prov", userAuthRole: "prov-role"}
		p, h, r := core.resolveUserAuthConfig(ctx, backend)
		assert.Equal(t, "auth/prov/", p)
		assert.Equal(t, "X-Prov", h)
		assert.Equal(t, "prov-role", r)
	})

	t.Run("namespace metadata fallback", func(t *testing.T) {
		ns := &namespace.Namespace{ID: "ns1", Path: "ns1/", CustomMetadata: map[string]string{
			"user_auth_path":    "auth/nsuser/",
			"user_token_header": "X-NS",
			"user_auth_role":    "ns-role",
		}}
		ctx := namespace.ContextWithNamespace(context.Background(), ns)
		p, h, r := core.resolveUserAuthConfig(ctx, &mockUserAuthProvider{}) // provider unset
		assert.Equal(t, "auth/nsuser/", p)
		assert.Equal(t, "X-NS", h)
		assert.Equal(t, "ns-role", r)
	})

	t.Run("unset everywhere yields empty", func(t *testing.T) {
		ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
		p, _, _ := core.resolveUserAuthConfig(ctx, &mockUserAuthProvider{})
		assert.Empty(t, p, "no provider/namespace config → feature off")
	})
}

// TestStampUserAttribution verifies the first observable consumer of req.User:
// the request audit entry records the user identity for attribution, and never
// the raw user credential.
func TestStampUserAttribution(t *testing.T) {
	core := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	userMount := mountStubAuthMethod(t, core, "user-jwt/", "jwt")
	userJWT := mintK8sJWT(`{"sub":"alice"}`)
	userTE := seedUserToken(t, core, ctx, userMount, userJWT, "slack-user", "alice")

	t.Run("stamps the user identity when req.User is set", func(t *testing.T) {
		req := &logical.Request{
			User: &logical.UserPrincipal{TokenEntry: userTE, RawToken: userJWT},
		}
		entry := core.buildRequestAuditEntry(ctx, req, &logical.Auth{}, nil, nil)
		require.NotNil(t, entry.Auth)
		require.NotNil(t, entry.Auth.User)
		// Subject is the user's raw principal (JWT sub), not the wid composite —
		// it matches warden_user.sub in the minted assertion.
		assert.Equal(t, userTE.PrincipalID, entry.Auth.User.Subject)
		assert.NotContains(t, entry.Auth.User.Subject, "wid:", "user attribution must be the raw sub, not the wid composite")
		assert.Equal(t, userTE.ID, entry.Auth.User.TokenID)
		assert.Equal(t, userTE.NamespaceID, entry.Auth.User.NamespaceID)

		// The raw user credential must never be serialized into an audit record.
		blob, err := json.Marshal(entry)
		require.NoError(t, err)
		assert.NotContains(t, string(blob), userJWT, "raw user credential must never be serialized")
	})

	t.Run("no user attribution when req.User is nil", func(t *testing.T) {
		req := &logical.Request{}
		entry := core.buildRequestAuditEntry(ctx, req, &logical.Auth{}, nil, nil)
		if entry.Auth != nil {
			assert.Nil(t, entry.Auth.User)
		}
	})
}

// TestProjectUserClaims covers the fail-closed user-claim projection: absent keys
// deny (unlike the metadata projection, which skips), and the size cap holds.
func TestProjectUserClaims(t *testing.T) {
	md := map[string]string{"username": "alice", "email": "alice@example.com"}

	t.Run("empty keys projects nothing", func(t *testing.T) {
		got, err := projectUserClaims(md, nil)
		require.NoError(t, err)
		assert.Nil(t, got)
	})
	t.Run("projects named keys", func(t *testing.T) {
		got, err := projectUserClaims(md, []string{"username"})
		require.NoError(t, err)
		assert.Equal(t, map[string]string{"username": "alice"}, got)
	})
	t.Run("absent key fails closed", func(t *testing.T) {
		_, err := projectUserClaims(md, []string{"username", "department"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "department")
	})
	t.Run("oversized projection fails closed", func(t *testing.T) {
		big := map[string]string{"k": strings.Repeat("x", maxAssertionMetadataBytes)}
		_, err := projectUserClaims(big, []string{"k"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exceed")
	})
}
