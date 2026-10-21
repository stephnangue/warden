package core

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
)

const testResourceBase = "https://warden.example.com"

// enableProtectedResource turns protected-resource metadata on, with
// testResourceBase as the external base.
func enableProtectedResource(t *testing.T, c *Core) {
	t.Helper()
	view := NewBarrierView(c.barrier, protectedResourceStorePrefix)
	require.NoError(t, saveProtectedResourceConfig(context.Background(), view,
		&protectedResourceConfig{ResourceURL: testResourceBase}))
	c.invalidateExternalBaseURL()
}

func TestResourceIDMatches(t *testing.T) {
	for _, tc := range []struct {
		v, base, ns, mount string
		want               bool
	}{
		{testResourceBase + "/v1/github", testResourceBase, "", "github/", true},
		{testResourceBase + "/v1/github", testResourceBase + "/", "", "github", true},
		{testResourceBase + "/v1/team-a/github", testResourceBase, "team-a/", "github/", true},
		{testResourceBase + "/v1/team-a/sub/github", testResourceBase, "team-a/sub/", "github/", true},

		// Another mount's identifier, or one that merely shares a prefix.
		{testResourceBase + "/v1/gitlab", testResourceBase, "", "github/", false},
		{testResourceBase + "/v1/github2", testResourceBase, "", "github/", false},
		{testResourceBase + "/v1/git", testResourceBase, "", "github/", false},
		{testResourceBase + "/v1/github", testResourceBase, "team-a/", "github/", false},
		{testResourceBase + "/v1/team-b/github", testResourceBase, "team-a/", "github/", false},
		{"https://other.example.com/v1/github", testResourceBase, "", "github/", false},

		// Non-canonical spellings of the same resource never match.
		{testResourceBase + "/v1/%67ithub", testResourceBase, "", "github/", false},
		{testResourceBase + "/v1/github%2F", testResourceBase, "", "github/", false},
		{testResourceBase + "/v1/./github", testResourceBase, "", "github/", false},
		{testResourceBase + "/v1/x/../github", testResourceBase, "", "github/", false},
		{testResourceBase + "/v1//github", testResourceBase, "", "github/", false},
		{testResourceBase + "/v1/github/", testResourceBase, "", "github/", false},
		{testResourceBase + "/V1/github", testResourceBase, "", "github/", false},
		{"HTTPS://WARDEN.EXAMPLE.COM/v1/github", testResourceBase, "", "github/", false},
		{testResourceBase + "/v1/team-a%2Fgithub", testResourceBase, "team-a/", "github/", false},

		// Nothing to compare against.
		{testResourceBase + "/v1/", testResourceBase, "", "", false},
		{"/v1/github", "", "", "github/", false},
	} {
		assert.Equal(t, tc.want, resourceIDMatches(tc.v, tc.base, tc.ns, tc.mount),
			"%q against base %q ns %q mount %q", tc.v, tc.base, tc.ns, tc.mount)
	}
	// Agrees with the identifier the metadata endpoint publishes.
	assert.True(t, resourceIDMatches(joinResourceURL(testResourceBase, "/v1/team-a/github"),
		testResourceBase, "team-a/", "github/"))
}

func TestResourceIDMatches_DoesNotAllocate(t *testing.T) {
	v := testResourceBase + "/v1/team-a/github"
	allocs := testing.AllocsPerRun(1000, func() {
		if !resourceIDMatches(v, testResourceBase+"/", "team-a/", "github/") {
			t.Fatal("no match")
		}
		if resourceIDMatches(v, testResourceBase, "team-a/", "gitlab/") {
			t.Fatal("match")
		}
	})
	assert.Zero(t, allocs)
}

// userLegFixture is a core with a jwt-like user mount at auth/user-jwt/ and a
// way to capture a user credential on a request to the provider at github/.
type userLegFixture struct {
	core  *Core
	ctx   context.Context
	mount *MountEntry
	n     int
}

func newUserLegFixture(t *testing.T) *userLegFixture {
	t.Helper()
	c := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	return &userLegFixture{core: c, ctx: ctx, mount: mountStubAuthMethod(t, c, "user-jwt/", "jwt")}
}

// credential seeds a fresh user credential admitted as adm and returns it.
func (f *userLegFixture) credential(t *testing.T, adm *logical.Admission) string {
	t.Helper()
	f.n++
	cred := mintK8sJWT(fmt.Sprintf(`{"sub":"user-%d"}`, f.n))
	seedUserTokenWith(t, f.core, f.ctx, f.mount, cred, fmt.Sprintf("user-%d", f.n), adm)
	return cred
}

// request is a gateway request to the provider mounted at github/.
func (f *userLegFixture) request(cred string) *logical.Request {
	hr := httptest.NewRequest(http.MethodPost, "/v1/github/role/agent/gateway", nil)
	hr.Header.Set("Authorization", "Bearer "+cred)
	return &logical.Request{
		Operation:   logical.CreateOperation,
		Path:        "github/gateway",
		MountPoint:  "github/",
		ClientToken: "agent-token",
		HTTPRequest: hr,
	}
}

func (f *userLegFixture) capture(req *logical.Request, cred string, refusal error) error {
	return f.core.captureUserContext(f.ctx, req, "auth/user-jwt/", refusal, cred)
}

// The user token's audience is bound by the user auth mount when it set
// bound_audiences at admission; otherwise by this mount's resource identifier
// when protected-resource metadata is on; otherwise the request is refused.
func TestUserLeg_AudiencePrecedence(t *testing.T) {
	resourceID := testResourceBase + "/v1/github"
	claims := func(aud any) map[string]any { return map[string]any{"sub": "alice", "aud": aud} }

	t.Run("without protected-resource metadata", func(t *testing.T) {
		f := newUserLegFixture(t)

		bound, _ := userAdmission(t, "auth/user-jwt/", claims("idp-client"), true)
		cred := f.credential(t, bound)
		req := f.request(cred)
		require.NoError(t, f.capture(req, cred, nil), "the mount's bound_audiences bind it")
		require.NotNil(t, req.User)

		unbound, _ := userAdmission(t, "auth/user-jwt/", claims(resourceID), false)
		cred = f.credential(t, unbound)
		req = f.request(cred)
		err := f.capture(req, cred, nil)
		var refused *userLegRefusal
		require.ErrorAs(t, err, &refused, "nothing binds it: refused for the configuration")
		assert.EqualError(t, err, "user token audience is not bound: set bound_audiences on auth/user-jwt/ or enable protected-resource metadata")
		assert.Nil(t, req.User)

		resp := f.core.userCaptureFailure(f.ctx, req, err)
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		assert.Empty(t, resp.Headers["WWW-Authenticate"], "no other credential would pass, so no challenge")
	})

	t.Run("with protected-resource metadata", func(t *testing.T) {
		f := newUserLegFixture(t)
		enableProtectedResource(t, f.core)

		for _, tc := range []struct {
			name  string
			aud   any
			bound bool
			ok    bool
		}{
			{"the exact resource identifier", resourceID, false, true},
			{"among several audiences", []any{"idp-client", resourceID}, false, true},
			{"another mount's identifier", testResourceBase + "/v1/gitlab", false, false},
			{"a prefix-sharing mount's identifier", testResourceBase + "/v1/github2", false, false},
			{"a percent-encoded spelling", testResourceBase + "/v1/%67ithub", false, false},
			{"a dot-segment spelling", testResourceBase + "/v1/./github", false, false},
			{"a trailing slash", resourceID + "/", false, false},
			{"another external base", "https://evil.example.com/v1/github", false, false},
			{"no audience at all", nil, false, false},
			{"a non-string audience", 42, false, false},
			// The mount's bound_audiences come first: what the mount checked
			// at admission binds it, whatever the identifier.
			{"bound at admission, other audience", "idp-client", true, true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				c := map[string]any{"sub": "alice"}
				if tc.aud != nil {
					c["aud"] = tc.aud
				}
				adm, _ := userAdmission(t, "auth/user-jwt/", c, tc.bound)
				cred := f.credential(t, adm)
				req := f.request(cred)
				err := f.capture(req, cred, nil)
				if tc.ok {
					require.NoError(t, err)
					require.NotNil(t, req.User)
					return
				}
				require.ErrorIs(t, err, errUserAudienceNotResource)
				assert.Nil(t, req.User)
				resp := f.core.userCaptureFailure(f.ctx, req, err)
				assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "a token for this resource would pass")
			})
		}
	})

	t.Run("the identifier names the request's namespace", func(t *testing.T) {
		f := newUserLegFixture(t)
		enableProtectedResource(t, f.core)
		adm, _ := userAdmission(t, "auth/user-jwt/", claims(testResourceBase+"/v1/team-a/github"), false)
		assert.NoError(t, f.core.checkUserAudience(f.ctx, adm, "team-a/", "github/", "auth/user-jwt/"))
		assert.ErrorIs(t, f.core.checkUserAudience(f.ctx, adm, "", "github/", "auth/user-jwt/"), errUserAudienceNotResource)
		assert.ErrorIs(t, f.core.checkUserAudience(f.ctx, adm, "team-b/", "github/", "auth/user-jwt/"), errUserAudienceNotResource)
	})
}

// Matching the identifier is a pointer-and-string walk: with the external
// base cached, a granted check does not allocate.
func TestCheckUserAudience_DoesNotAllocate(t *testing.T) {
	f := newUserLegFixture(t)
	enableProtectedResource(t, f.core)
	adm, _ := userAdmission(t, "auth/user-jwt/", map[string]any{
		"sub": "alice", "aud": []any{"idp-client", testResourceBase + "/v1/team-a/github"},
	}, false)
	require.NoError(t, f.core.checkUserAudience(f.ctx, adm, "team-a/", "github/", "auth/user-jwt/"))
	allocs := testing.AllocsPerRun(1000, func() {
		if err := f.core.checkUserAudience(f.ctx, adm, "team-a/", "github/", "auth/user-jwt/"); err != nil {
			t.Fatal(err)
		}
	})
	assert.Zero(t, allocs)
}

// A provider whose stored config still names user_auth_role refuses every user
// credential before admitting it, for its configuration, without a challenge.
func TestUserLeg_StoredUserAuthRoleRefused(t *testing.T) {
	f := newUserLegFixture(t)
	cred := mintK8sJWT(`{"sub":"never-admitted"}`)
	req := f.request(cred)

	err := f.capture(req, cred, framework.ErrUserAuthRoleRemoved)
	var refused *userLegRefusal
	require.ErrorAs(t, err, &refused)
	require.ErrorIs(t, err, framework.ErrUserAuthRoleRemoved)
	assert.EqualError(t, err, "user_auth_role was removed: the token audience is now bound by the user auth "+
		"mount's bound_audiences, or by this mount's resource identifier; remove user_auth_role to continue")
	assert.Nil(t, req.User)
	assert.Empty(t, req.HTTPRequest.Header.Get("Authorization"), "the user credential is still scrubbed")

	ttype := f.core.tokenStore.GetTransparentTokenTypeForAuthMethod("jwt")
	te, _ := f.core.LookupTransparentToken(f.ctx, ttype, cred, f.mount.Accessor)
	assert.Nil(t, te, "the credential is not admitted at all")

	resp := f.core.userCaptureFailure(f.ctx, req, err)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Empty(t, resp.Headers["WWW-Authenticate"])

	// Without a user credential there is nothing to refuse.
	req = f.request("")
	require.NoError(t, f.capture(req, "", framework.ErrUserAuthRoleRemoved))
	assert.Nil(t, req.User)
}

// The user's metadata is rendered from its admission under the user mount's
// naming in force: user.metadata.<key> conditions and assertion_user_claims
// read it, a facts edit on the user mount applies on the next request, the
// steady state does not allocate, and the cached token entry is never written.
func TestUserLeg_Metadata(t *testing.T) {
	f := newUserLegFixture(t)
	adm, mountFacts := userAdmission(t, "auth/user-jwt/", map[string]any{
		"sub": "alice", "department": "eng", "aud": "idp-client",
	}, true)
	cred := f.credential(t, adm)

	agentTE := &logical.TokenEntry{PrincipalID: "agent-1"}
	allows := func(t *testing.T, req *logical.Request, condition string) bool {
		t.Helper()
		policy := testParsePolicy(t, `
			path "github/gateway" {
				capabilities = ["create"]
				condition = "`+condition+`"
			}
		`)
		cbp, err := NewCBP(testContext(), []*Policy{policy})
		require.NoError(t, err)
		return cbp.AllowOperation(testContext(), req, agentTE, false).Allowed
	}

	req := f.request(cred)
	require.NoError(t, f.capture(req, cred, nil))
	assert.Equal(t, map[string]string{"dept": "eng"}, req.User.TokenEntry.Metadata)
	assert.Equal(t, "user-1", req.User.TokenEntry.PrincipalID, "the principal is the mount's claim, from the login")
	assert.True(t, allows(t, req, "user.present && user.metadata.dept == 'eng'"))
	assert.False(t, allows(t, req, "user.present && user.metadata.dept == 'ops'"))

	claims, fingerprint, err := projectUserClaims(req.User.TokenEntry.Metadata, []string{"dept"})
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"dept": "eng"}, claims)

	// The steady state is the cached render: the same map, no allocation.
	first := userMetadata(adm, time.Now())
	assert.Equal(t, reflect.ValueOf(first).Pointer(), reflect.ValueOf(userMetadata(adm, time.Now())).Pointer())
	allocs := testing.AllocsPerRun(1000, func() { _ = userMetadata(adm, time.Now()) })
	assert.Zero(t, allocs)

	// A facts edit on the user mount reaches the next request on the same
	// cached credential.
	mountFacts.Publish(testNaming(t, logical.EntityKindHuman, map[string]string{"department": "team"}))
	req = f.request(cred)
	require.NoError(t, f.capture(req, cred, nil))
	assert.Equal(t, map[string]string{"team": "eng"}, req.User.TokenEntry.Metadata)
	assert.False(t, allows(t, req, "user.present && user.metadata.dept == 'eng'"))
	assert.True(t, allows(t, req, "user.present && user.metadata.team == 'eng'"))
	_, _, err = projectUserClaims(req.User.TokenEntry.Metadata, []string{"dept"})
	assert.ErrorContains(t, err, `"dept"`, "a claim the mapping no longer names fails closed")
	_, after, err := projectUserClaims(req.User.TokenEntry.Metadata, []string{"team"})
	require.NoError(t, err)
	assert.NotEqual(t, fingerprint, after, "the credential cache keys the new claims apart")

	// The cached entry holds no metadata of its own: every request renders
	// onto its own copy.
	ttype := f.core.tokenStore.GetTransparentTokenTypeForAuthMethod("jwt")
	cached, err := f.core.LookupTransparentToken(f.ctx, ttype, cred, f.mount.Accessor)
	require.NoError(t, err)
	assert.Nil(t, cached.Metadata)
	assert.Empty(t, cached.Policies)
	assert.Empty(t, cached.RoleName)
}

// Concurrent requests on one cached user credential each render the metadata
// onto their own copy while the user mount's naming changes; run under -race.
func TestUserLeg_MetadataConcurrent(t *testing.T) {
	f := newUserLegFixture(t)
	adm, mountFacts := userAdmission(t, "auth/user-jwt/", map[string]any{"sub": "alice", "department": "eng"}, true)
	cred := f.credential(t, adm)

	namings := []*logical.MountNaming{
		testNaming(t, logical.EntityKindHuman, map[string]string{"department": "dept"}),
		testNaming(t, logical.EntityKindHuman, map[string]string{"department": "team"}),
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 50; i++ {
			mountFacts.Publish(namings[i%2])
		}
	}()
	errs := make(chan error, 8)
	for g := 0; g < 8; g++ {
		go func() {
			for i := 0; i < 50; i++ {
				req := f.request(cred)
				if err := f.capture(req, cred, nil); err != nil {
					errs <- err
					return
				}
				if len(req.User.TokenEntry.Metadata) != 1 {
					errs <- errors.New("want one rendered key")
					return
				}
			}
			errs <- nil
		}()
	}
	for g := 0; g < 8; g++ {
		require.NoError(t, <-errs)
	}
	<-done
}

// mockAudienceBinder is an auth backend whose configuration does or does not
// bind audiences.
type mockAudienceBinder struct {
	mockTransparentModeProvider
	binds bool
}

func (m *mockAudienceBinder) BindsAudience() bool { return m.binds }

// A provider config read warns ahead of time when its user leg would refuse
// every user credential.
func TestUserLegConfigWarnings(t *testing.T) {
	c := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	mountProvider := func(path, userAuthPath string, refusal error) *MountEntry {
		entry := &MountEntry{
			Path: path, Type: "mcp", Class: mountClassProvider,
			UUID: "prov-" + path, Accessor: "acc-" + path,
			NamespaceID: namespace.RootNamespaceID, namespace: namespace.RootNamespace,
		}
		backend := &mockUnauthPathBackend{userAuthPath: userAuthPath, userAuthRefusal: refusal}
		require.NoError(t, c.router.Mount(path, backend, entry, &mockBarrierView{prefix: "provider/" + path}))
		return entry
	}
	mountStubAuthMethod(t, c, "user-jwt/", "jwt") // no AudienceBinder: binds nothing it can name
	bindingEntry := &MountEntry{
		Path: "bound-jwt/", Type: "jwt", Class: mountClassAuth, UUID: "auth-bound", Accessor: "auth_jwt_bound",
		NamespaceID: namespace.RootNamespaceID, namespace: namespace.RootNamespace,
	}
	require.NoError(t, c.router.Mount(authRoutePrefix+"bound-jwt/", &mockAudienceBinder{binds: true},
		bindingEntry, NewBarrierView(c.barrier, "auth/auth-bound/")))

	refused := mountProvider("refused/", "auth/user-jwt/", framework.ErrUserAuthRoleRemoved)
	unbound := mountProvider("unbound/", "auth/user-jwt", nil)
	bound := mountProvider("bound/", "auth/bound-jwt/", nil)
	plain := mountProvider("plain/", "", nil)

	assert.Equal(t, []string{"user credentials are refused: " + framework.ErrUserAuthRoleRemoved.Error()},
		c.userLegConfigWarnings(ctx, refused))
	assert.Equal(t, []string{"user token audience is not bound: set bound_audiences on auth/user-jwt/ or enable " +
		"protected-resource metadata; until then every user credential is refused"}, c.userLegConfigWarnings(ctx, unbound))
	assert.Empty(t, c.userLegConfigWarnings(ctx, bound), "the user mount binds audiences")
	assert.Empty(t, c.userLegConfigWarnings(ctx, plain), "no user leg, nothing to warn about")

	enableProtectedResource(t, c)
	assert.Empty(t, c.userLegConfigWarnings(ctx, unbound), "the resource identifier binds it")
	assert.Len(t, c.userLegConfigWarnings(ctx, refused), 1, "a stored user_auth_role refuses whatever binds")
}

// A provider config read warns when its auto_auth_path names a human auth
// mount, or its user_auth_path an agent one; a path naming no auth mount, or
// a mount that publishes no kind, is not a kind warning.
func TestAuthMountKindWarnings(t *testing.T) {
	c := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	for path, kind := range map[string]string{"agents/": logical.EntityKindAgent, "humans/": logical.EntityKindHuman} {
		typ := "kind-" + strings.TrimSuffix(path, "/")
		c.authMethods[typ] = func(context.Context, *logical.BackendConfig) (logical.Backend, error) {
			return &factsBackend{typ: typ, kind: kind}, nil
		}
		require.NoError(t, c.mount(ctx, &MountEntry{Class: mountClassAuth, Type: typ, Path: path}))
	}
	mountStubAuthMethod(t, c, "stub/", "jwt") // publishes no kind

	mountProvider := func(path, autoAuthPath, userAuthPath string) *MountEntry {
		entry := &MountEntry{
			Path: path, Type: "mcp", Class: mountClassProvider,
			UUID: "prov-" + path, Accessor: "acc-" + path,
			NamespaceID: namespace.RootNamespaceID, namespace: namespace.RootNamespace,
		}
		backend := &mockUnauthPathBackend{userAuthPath: userAuthPath}
		backend.transparentMode, backend.autoAuthPath = autoAuthPath != "", autoAuthPath
		require.NoError(t, c.router.Mount(path, backend, entry, &mockBarrierView{prefix: "provider/" + path}))
		return entry
	}
	kindWarnings := func(entry *MountEntry) []string {
		return c.authMountKindWarnings(ctx, c.router.MatchingBackend(ctx, entry.Path))
	}

	humanAgentLeg := mountProvider("human-agent-leg/", "auth/humans/", "")
	assert.Equal(t, []string{`auto_auth_path "auth/humans/" names a human auth mount: ` +
		"agent credentials are never admitted through it, so every gateway request is refused"}, kindWarnings(humanAgentLeg))
	assert.Equal(t, kindWarnings(humanAgentLeg), c.providerConfigWarnings(ctx, humanAgentLeg), "no user leg")

	agentUserLeg := mountProvider("agent-user-leg/", "auth/agents/", "auth/agents")
	assert.Equal(t, []string{`user_auth_path "auth/agents" names an agent auth mount: ` +
		"user credentials are expected through a human auth mount"}, kindWarnings(agentUserLeg))
	assert.Contains(t, c.providerConfigWarnings(ctx, agentUserLeg), kindWarnings(agentUserLeg)[0],
		"the config read carries it with the user-leg warnings")

	assert.Empty(t, kindWarnings(mountProvider("right-kinds/", "auth/agents/", "auth/humans/")))
	assert.Empty(t, kindWarnings(mountProvider("no-mounts/", "auth/nowhere/", "auth/nobody/")))
	assert.Empty(t, kindWarnings(mountProvider("no-kind/", "auth/stub/", "auth/stub/")))
	assert.Empty(t, kindWarnings(mountProvider("no-paths/", "", "")))
}

// Enabling a provider with the removed user_auth_role is refused.
func TestProviderCreate_RefusesUserAuthRole(t *testing.T) {
	backend, ctx, c := setupTestSystemBackend(t)
	c.providers["mock"] = MockProviderFactory
	var schema map[string]*framework.FieldSchema
	for _, p := range backend.pathProviders() {
		if p.Pattern == "providers/"+framework.MatchAllRegex("path") {
			schema = p.Fields
		}
	}
	require.NotNil(t, schema)
	raw := map[string]any{
		"path": "gh", "type": "mock",
		"config": map[string]any{"user_auth_path": "auth/user-jwt/", "user_auth_role": "slack-user"},
	}
	resp, err := backend.handleProviderCreate(ctx, createTestRequest(logical.CreateOperation, "providers/gh", raw), createFieldData(schema, raw))
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.EqualError(t, resp.Err, framework.ErrUserAuthRoleRemoved.Error())
}

// Enabling an auth method with a configuration key of the role era is refused.
func TestAuthCreate_RefusesRemovedConfigKeys(t *testing.T) {
	backend, ctx, c := setupTestSystemBackend(t)
	c.authMethods["mock"] = MockProviderFactory
	schema := backend.pathAuth()[0].Fields
	raw := map[string]any{
		"path": "jwt", "type": "mock",
		"config": map[string]any{"default_role": "reader", "groups_claim": "groups"},
	}
	resp, err := backend.handleAuthCreate(ctx, createTestRequest(logical.CreateOperation, "auth/jwt", raw), createFieldData(schema, raw))
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.ErrorContains(t, resp.Err, "default_role was removed")
	assert.ErrorContains(t, resp.Err, "groups_claim was removed")
}

// recordingBarrier records every storage operation on a key under an auth
// mount's role/ prefix.
type recordingBarrier struct {
	SecurityBarrier
	lists, others int
}

func isRoleKey(key string) bool { return strings.Contains(key, "/role/") }

func (r *recordingBarrier) List(ctx context.Context, prefix string) ([]string, error) {
	if isRoleKey(prefix) {
		r.lists++
	}
	return r.SecurityBarrier.List(ctx, prefix)
}

func (r *recordingBarrier) Get(ctx context.Context, key string) (*sdklogical.StorageEntry, error) {
	if isRoleKey(key) {
		r.others++
	}
	return r.SecurityBarrier.Get(ctx, key)
}

func (r *recordingBarrier) Put(ctx context.Context, entry *sdklogical.StorageEntry) error {
	if isRoleKey(entry.Key) {
		r.others++
	}
	return r.SecurityBarrier.Put(ctx, entry)
}

func (r *recordingBarrier) Delete(ctx context.Context, key string) error {
	if isRoleKey(key) {
		r.others++
	}
	return r.SecurityBarrier.Delete(ctx, key)
}

// Auth roles an older version stored are counted once per mount at unseal,
// reported by sys/auth, and never read or changed.
func TestAuthRoleLeftovers(t *testing.T) {
	backend, ctx, c := setupTestSystemBackend(t)
	old := mountStubAuthMethod(t, c, "jwt-old/", "jwt")
	oldCert := mountStubAuthMethod(t, c, "cert-old/", "cert")
	fresh := mountStubAuthMethod(t, c, "fresh/", "jwt")

	seed := func(entry *MountEntry, keys ...string) BarrierView {
		view := NewBarrierView(c.barrier, "auth/"+entry.UUID+"/")
		for _, k := range keys {
			require.NoError(t, view.Put(ctx, &sdklogical.StorageEntry{Key: k, Value: []byte(`{"name":"` + k + `"}`)}))
		}
		return view
	}
	oldView := seed(old, "role/deploy", "role/read", "config")
	seed(oldCert, "role/ci")
	seed(fresh, "config")

	recorder := &recordingBarrier{SecurityBarrier: c.barrier}
	c.barrier = recorder
	c.detectAuthRoleLeftovers(ctx)
	c.authLock.RLock()
	mounts := len(c.auth.Entries)
	c.authLock.RUnlock()
	assert.Equal(t, mounts, recorder.lists, "one list per auth mount")
	assert.Zero(t, recorder.others, "the old roles are never read or written")

	assert.Equal(t, 2, c.authRoleLeftoverCount(old.UUID))
	assert.Equal(t, 1, c.authRoleLeftoverCount(oldCert.UUID))
	assert.Zero(t, c.authRoleLeftoverCount(fresh.UUID))

	resp, err := backend.handleAuthList(ctx, createTestRequest(logical.ListOperation, "auth", nil), createFieldData(nil, nil))
	require.NoError(t, err)
	assert.Equal(t, []string{
		"auth/cert-old/: 1 auth roles are no longer used; recreate them as roles and groups (see upgrade notes)",
		"auth/jwt-old/: 2 auth roles are no longer used; recreate them as roles and groups (see upgrade notes)",
	}, resp.Data["warnings"])

	schema := backend.pathAuth()[0].Fields
	read := func(path string) *logical.Response {
		raw := map[string]any{"path": path}
		resp, err := backend.handleAuthRead(ctx, createTestRequest(logical.ReadOperation, "auth/"+path, raw), createFieldData(schema, raw))
		require.NoError(t, err)
		return resp
	}
	assert.Equal(t, []string{authRoleLeftoverWarning("jwt-old/", 2)}, read("jwt-old").Data["warnings"])
	assert.NotContains(t, read("fresh").Data, "warnings")

	// Storage is left as it was, so a rollback finds the roles.
	got, err := oldView.Get(ctx, "role/deploy")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, `{"name":"role/deploy"}`, string(got.Value))

	// The next active node counts again.
	c.authRoleLeftovers.Store(nil)
	assert.Zero(t, c.authRoleLeftoverCount(old.UUID))
}

// Disabling an auth mount a group rule lists, exactly or by a pattern, warns
// with how many groups list it, naming neither the groups nor their selectors.
func TestAuthDelete_WarnsAboutListingGroups(t *testing.T) {
	backend, ctx, c := setupTestSystemBackend(t)
	c.authMethods["mock"] = MockProviderFactory
	schema := backend.pathAuth()[0].Fields
	enable := func(path string) {
		raw := map[string]any{"path": path, "type": "mock"}
		resp, err := backend.handleAuthCreate(ctx, createTestRequest(logical.CreateOperation, "auth/"+path, raw), createFieldData(schema, raw))
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, resp.StatusCode, "%v", resp.Err)
	}
	disable := func(path string) *logical.Response {
		raw := map[string]any{"path": path}
		resp, err := backend.handleAuthDelete(ctx, createTestRequest(logical.DeleteOperation, "auth/"+path, raw), createFieldData(schema, raw))
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
		return resp
	}
	enable("ci-jwt")
	enable("other")

	for _, g := range []*logical.Group{
		{Name: "exact-secret-name", Type: logical.GroupTypeVirtual, Roles: []string{"deploy"},
			Rules: []logical.GroupRule{{"mount": {"auth/ci-jwt/"}, "sub": {"build-*"}}}},
		{Name: "glob-secret-name", Type: logical.GroupTypeVirtual, Roles: []string{"deploy"},
			Rules: []logical.GroupRule{{"mount": {"auth/ci-*/"}}, {"mount": {"auth/ci-jwt/"}}}},
		{Name: "unrelated", Type: logical.GroupTypeVirtual, Roles: []string{"deploy"},
			Rules: []logical.GroupRule{{"mount": {"auth/elsewhere/"}}}},
	} {
		_, err := c.identityStore.CreateGroup(ctx, g)
		require.NoError(t, err)
	}

	resp := disable("ci-jwt")
	warnings, _ := resp.Data["warnings"].([]string)
	require.Len(t, warnings, 1)
	assert.Equal(t, "2 group(s) have a rule whose mount selector names auth/ci-jwt/; those rules match nothing "+
		"until a mount is enabled there again", warnings[0])
	for _, secret := range []string{"exact-secret-name", "glob-secret-name", "build-*", "ci-*"} {
		assert.NotContains(t, warnings[0], secret)
	}

	assert.NotContains(t, disable("other").Data, "warnings", "no group lists it")
}
