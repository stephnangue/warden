package core

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	gojwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/audit"
	jwtmethod "github.com/stephnangue/warden/auth/method/jwt"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
)

// The tests here drive real jwt logins through implicit auth: every login is
// an admission, and the role is granted per request.

// countingBackend wraps a real auth backend, counting its logins. When gate is
// set, each login reports on entered and waits for gate to close.
type countingBackend struct {
	logical.Backend
	logins  atomic.Int64
	gate    chan struct{}
	entered chan struct{}
}

func (b *countingBackend) HandleRequest(ctx context.Context, req *logical.Request) (*logical.Response, error) {
	if req.Path == "login" {
		b.logins.Add(1)
		if b.gate != nil {
			b.entered <- struct{}{}
			<-b.gate
		}
	}
	return b.Backend.HandleRequest(ctx, req)
}

// jwtEnv is a core with real jwt auth mounts trusting one signing key, in the
// root namespace or a child one.
type jwtEnv struct {
	t      *testing.T
	c      *Core
	ns     *namespace.Namespace
	ctx    context.Context
	key    *ecdsa.PrivateKey
	pubPEM string

	// gated makes the next mounted backend hold its logins.
	gated   bool
	created *countingBackend
}

func newJWTEnv(t *testing.T, nsPath string) *jwtEnv {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	e := &jwtEnv{
		t: t, c: createTestCore(t), ns: namespace.RootNamespace, ctx: rootCtx(), key: key,
		pubPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
	}
	if nsPath != "" {
		ns := &namespace.Namespace{Path: nsPath}
		require.NoError(t, e.c.namespaceStore.SetNamespace(rootCtx(), ns))
		e.ns = ns
		e.ctx = namespace.ContextWithNamespace(context.Background(), ns)
	}
	e.c.authMethods["jwt"] = func(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
		b, err := jwtmethod.Factory(ctx, conf)
		if err != nil {
			return nil, err
		}
		cb := &countingBackend{Backend: b}
		if e.gated {
			cb.gate, cb.entered = make(chan struct{}), make(chan struct{}, 64)
		}
		e.created = cb
		return cb, nil
	}
	return e
}

// mount mounts a jwt auth method at auth/<path> trusting the env's key,
// configured with config (bound_audiences "warden" unless config sets
// entity_kind or bound_audiences).
func (e *jwtEnv) mount(path string, config map[string]any) *countingBackend {
	e.t.Helper()
	require.NoError(e.t, e.c.mount(e.ctx, &MountEntry{Class: mountClassAuth, Type: "jwt", Path: path}))
	b := e.created
	conf := map[string]any{"jwt_validation_pubkeys": []string{e.pubPEM}}
	_, kind := config["entity_kind"]
	_, auds := config["bound_audiences"]
	if !kind && !auds {
		conf["bound_audiences"] = "warden"
	}
	for k, v := range config {
		conf[k] = v
	}
	e.writeConfig(b, conf)
	return b
}

func (e *jwtEnv) writeConfig(b *countingBackend, data map[string]any) {
	e.t.Helper()
	resp, err := b.HandleRequest(e.ctx, &logical.Request{Operation: logical.UpdateOperation, Path: "config", Data: data})
	require.NoError(e.t, err)
	require.Less(e.t, resp.StatusCode, 300, "config write: %v", resp.Err)
}

// token signs a JWT for sub with audience aud ("warden" when empty).
func (e *jwtEnv) token(sub, aud string) string {
	e.t.Helper()
	if aud == "" {
		aud = "warden"
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: e.key}, new(jose.SignerOptions).WithType("JWT"))
	require.NoError(e.t, err)
	now := time.Now()
	tok, err := gojwt.Signed(signer).Claims(gojwt.Claims{
		Subject: sub, Audience: gojwt.Audience{aud},
		IssuedAt: gojwt.NewNumericDate(now), Expiry: gojwt.NewNumericDate(now.Add(time.Hour)),
	}).Serialize()
	require.NoError(e.t, err)
	return tok
}

func (e *jwtEnv) policy(name string) {
	e.t.Helper()
	p, err := ParseCBPPolicy(e.ns, `path "secret/*" { capabilities = ["read"] }`)
	require.NoError(e.t, err)
	p.Name, p.Type = name, PolicyTypeCBP
	require.NoError(e.t, e.c.policyStore.SetPolicy(e.ctx, p, nil))
}

// implicit runs implicit auth for token at auth/<mount> asking for role, as
// the gateway does.
func (e *jwtEnv) implicit(mount, token, role string) (*logical.Request, error) {
	req := &logical.Request{Operation: logical.ReadOperation, Path: "secret/x", ClientToken: token}
	provider := &mockTransparentModeProvider{transparentMode: true, autoAuthPath: "auth/" + mount}
	return req, e.c.handleTransparentAuth(e.ctx, req, provider, role)
}

// request runs implicit auth, then CheckToken, as a gateway request does.
func (e *jwtEnv) request(mount, token, role string) (*logical.Request, *logical.TokenEntry, error) {
	e.t.Helper()
	req, err := e.implicit(mount, token, role)
	if err != nil {
		return req, nil, err
	}
	_, _, te, err := e.c.CheckToken(e.ctx, req, false)
	return req, te, err
}

// cached returns the admission token the cache holds for token at mount.
func (e *jwtEnv) cached(mount, token string) *TokenEntry {
	e.t.Helper()
	entry := e.c.router.MatchingMountEntry(e.ctx, "auth/"+mount)
	require.NotNil(e.t, entry)
	id := (&JWTRoleTokenType{}).ComputeID((&JWTRoleTokenType{}).LookupValue(token, entry.Accessor))
	te, ok := e.c.tokenStore.byID.Get(id)
	if !ok {
		return nil
	}
	return te
}

// A real login issues an admission token carrying no role, spec, policies or
// metadata; a group grants the requested role per request, through the mount
// named relative to the namespace, in the root and in a child namespace alike.
func TestAdmissionLogin_GrantedPerRequest(t *testing.T) {
	for _, nsPath := range []string{"", "team/"} {
		t.Run("namespace "+nsPath, func(t *testing.T) {
			e := newJWTEnv(t, nsPath)
			e.mount("jwt/", map[string]any{"facts": map[string]any{"sub": "sub"}})
			e.policy("read")
			group := grantRole(t, e.c, e.ctx, testGrant{
				Role: "reader", Policies: []string{"read"}, Spec: "read-spec", Mount: "auth/jwt/",
				Rule: map[string][]string{"sub": {"agent-*"}},
			})
			token := e.token("agent-1", "")

			req, te, err := e.request("jwt/", token, "reader")
			require.NoError(t, err)
			require.True(t, req.RoleGrant().Granted())
			assert.Equal(t, "group:"+group, req.RoleGrant().GrantedBy)
			assert.Equal(t, "reader", te.RoleName)
			assert.Equal(t, []string{"read"}, te.Policies)
			assert.Equal(t, "read-spec", te.CredentialSpec)
			assert.Equal(t, map[string]string{"sub": "agent-1"}, te.Metadata, "metadata is the membership's rendering")
			assert.Equal(t, "auth/jwt/", te.Admission.MountPath, "namespace-relative, whatever the namespace")
			assert.Equal(t, e.ns.ID, te.NamespaceID)

			cached := e.cached("jwt/", token)
			require.NotNil(t, cached)
			assert.Empty(t, cached.RoleName)
			assert.Empty(t, cached.CredentialSpec)
			assert.Nil(t, cached.Policies)
			assert.Nil(t, cached.Metadata)
			assert.Same(t, te.Admission, cached.Admission)

			// Outside the rule: admitted, then refused per request.
			req, _, err = e.request("jwt/", e.token("ci-bot", ""), "reader")
			requireDenied(t, req, err, logical.RoleDeniedNotAssumable)
		})
	}
}

// One credential at one mount is one admission token and one login, whatever
// role each request asks for; each request sees its own role.
func TestAdmissionLogin_OneEntryAcrossRoles(t *testing.T) {
	e := newJWTEnv(t, "")
	b := e.mount("jwt/", nil)
	e.policy("read")
	e.policy("write")
	grantRole(t, e.c, e.ctx, testGrant{Role: "reader", Policies: []string{"read"}, Mount: "auth/jwt/"})
	grantRole(t, e.c, e.ctx, testGrant{Role: "writer", Policies: []string{"write"}, Mount: "auth/jwt/"})
	token := e.token("agent-1", "")

	_, reader, err := e.request("jwt/", token, "reader")
	require.NoError(t, err)
	_, writer, err := e.request("jwt/", token, "writer")
	require.NoError(t, err)

	assert.EqualValues(t, 1, b.logins.Load(), "the second role reuses the admission")
	assert.Equal(t, reader.ID, writer.ID)
	assert.Equal(t, []string{"read"}, reader.Policies)
	assert.Equal(t, []string{"write"}, writer.Policies)
	assert.Same(t, reader.Admission, writer.Admission)
}

// N concurrent first requests for one credential, under two roles, share one
// login; each request gets its own copy of the entry and its own projection,
// and the cached entry stays unprojected (-race).
func TestAdmissionLogin_PerWaiterCopyEndToEnd(t *testing.T) {
	e := newJWTEnv(t, "")
	e.gated = true
	b := e.mount("jwt/", nil)
	e.policy("read")
	e.policy("write")
	grantRole(t, e.c, e.ctx, testGrant{Role: "reader", Policies: []string{"read"}, Mount: "auth/jwt/"})
	grantRole(t, e.c, e.ctx, testGrant{Role: "writer", Policies: []string{"write"}, Mount: "auth/jwt/"})
	token := e.token("agent-1", "")

	const n = 8
	type result struct {
		role string
		req  *logical.Request
		te   *logical.TokenEntry
		err  error
	}
	results := make(chan result, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		role := []string{"reader", "writer"}[i%2]
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, te, err := e.request("jwt/", token, role)
			results <- result{role, req, te, err}
		}()
		if i == 0 {
			receiveWithin(t, b.entered, "the first login to start")
		}
	}
	time.Sleep(50 * time.Millisecond) // let the others join the login in flight
	close(b.gate)
	wg.Wait()
	close(results)

	require.EqualValues(t, 1, b.logins.Load(), "one login served every request")
	seen := map[*logical.TokenEntry]bool{}
	var adm *logical.Admission
	for r := range results {
		require.NoError(t, r.err)
		require.False(t, seen[r.te], "two requests share one *TokenEntry")
		seen[r.te] = true
		assert.Equal(t, r.role, r.te.RoleName)
		assert.Equal(t, r.role, r.req.RoleGrant().RoleName)
		want := map[string][]string{"reader": {"read"}, "writer": {"write"}}[r.role]
		assert.Equal(t, want, r.te.Policies)
		if adm == nil {
			adm = r.te.Admission
		}
		assert.Same(t, adm, r.te.Admission, "every copy shares the one admission")
	}
	cached := e.cached("jwt/", token)
	require.NotNil(t, cached)
	assert.Empty(t, cached.RoleName)
	assert.Nil(t, cached.Policies)
}

// gwProvider is a gateway provider that reads the agent's bearer from
// Authorization.
type gwProvider struct{ mockTransparentModeProvider }

func (p *gwProvider) ExtractTokens(r *http.Request, _ bool) (string, string) {
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), ""
}

// A request that selects no role is refused with 400 before its credential
// is admitted, on the gateway and on transparent operations alike: no login
// runs and nothing is cached.
func TestAdmissionLogin_NoRoleSelected(t *testing.T) {
	e := newJWTEnv(t, "")
	b := e.mount("jwt/", nil)
	grantRole(t, e.c, e.ctx, testGrant{Role: "reader", Policies: []string{"read"}, Mount: "auth/jwt/"})
	token := e.token("agent-1", "")
	mountGateway(t, e.c, "gw/", &gwProvider{mockTransparentModeProvider{transparentMode: true, autoAuthPath: "auth/jwt/"}})

	t.Run("gateway", func(t *testing.T) {
		hr := httptest.NewRequest(http.MethodGet, "/v1/gw/gateway/x", nil)
		hr.Header.Set("Authorization", "Bearer "+token)
		req := &logical.Request{Path: "gw/gateway/x", Operation: logical.ReadOperation, HTTPRequest: hr}
		resp, _, _ := e.c.handleNonLoginRequest(e.ctx, req)
		require.NotNil(t, resp)
		require.Error(t, resp.Err)
		assert.Equal(t, http.StatusBadRequest, logical.GetErrorCode(resp.Err))
		assert.Contains(t, resp.Err.Error(), noRoleSelectedGateway)
		assert.Nil(t, req.TokenEntry())
	})

	t.Run("transparent operations", func(t *testing.T) {
		withAuth := &namespace.Namespace{
			ID: namespace.RootNamespaceID, Path: "",
			CustomMetadata: map[string]string{"auto_auth_path": "auth/jwt/"},
		}
		ctx := namespace.ContextWithNamespace(context.Background(), withAuth)
		hr := httptest.NewRequest(http.MethodGet, "/v1/sys/cred/sources", nil)
		hr.Header.Set("Authorization", "Bearer "+token)
		req := &logical.Request{Path: "sys/cred/sources", Operation: logical.ReadOperation, HTTPRequest: hr}
		resp, _, _ := e.c.handleNonLoginRequest(ctx, req)
		require.NotNil(t, resp)
		require.Error(t, resp.Err)
		assert.Equal(t, http.StatusBadRequest, logical.GetErrorCode(resp.Err))
		assert.Contains(t, resp.Err.Error(), noRoleSelectedOperations)
		assert.Nil(t, req.TokenEntry())
	})

	// A request with no credential at all is unauthenticated first: 401, so
	// the client authenticates (an OAuth challenge, git's Basic retry).
	t.Run("gateway without a credential", func(t *testing.T) {
		hr := httptest.NewRequest(http.MethodGet, "/v1/gw/gateway/x", nil)
		req := &logical.Request{Path: "gw/gateway/x", Operation: logical.ReadOperation, HTTPRequest: hr}
		resp, _, _ := e.c.handleNonLoginRequest(e.ctx, req)
		require.NotNil(t, resp)
		require.Error(t, resp.Err)
		assert.Equal(t, http.StatusUnauthorized, logical.GetErrorCode(resp.Err))
		assert.Nil(t, req.TokenEntry())
	})

	// git sends the role as the Basic username only after a challenge, so a
	// git request that selects no role is challenged with 401, not refused
	// with 400.
	t.Run("gateway git smart-HTTP", func(t *testing.T) {
		hr := httptest.NewRequest(http.MethodGet, "/v1/gw/gateway/acme/widgets.git/info/refs?service=git-upload-pack", nil)
		hr.Header.Set("Authorization", "Bearer "+token)
		req := &logical.Request{Path: "gw/gateway/acme/widgets.git/info/refs", Operation: logical.ReadOperation, HTTPRequest: hr}
		resp, _, _ := e.c.handleNonLoginRequest(e.ctx, req)
		require.NotNil(t, resp)
		require.Error(t, resp.Err)
		assert.Equal(t, http.StatusUnauthorized, logical.GetErrorCode(resp.Err))
		assert.Contains(t, resp.Err.Error(), noRoleSelectedGateway)
		assert.Equal(t, `Basic realm="warden"`, resp.Headers.Get("WWW-Authenticate"))
		assert.Nil(t, req.TokenEntry())
	})

	assert.Zero(t, b.logins.Load(), "no login ran")
	assert.Nil(t, e.cached("jwt/", token), "nothing was cached")

	// The provider's default_role selects a role.
	provider := &mockTransparentModeProvider{transparentMode: true, autoAuthPath: "auth/jwt/", defaultAuthRole: "reader"}
	req := &logical.Request{Operation: logical.ReadOperation, Path: "gw/gateway/x", MountPoint: "gw/", ClientToken: token}
	ok, role := e.c.isTransparentRequest(req, provider)
	require.True(t, ok)
	require.Equal(t, "reader", role)
	require.NoError(t, e.c.handleTransparentAuth(e.ctx, req, provider, role))
	assert.EqualValues(t, 1, b.logins.Load())
}

// On transparent operations a ?role= that is present but empty selects
// nothing, so X-Warden-Role stays in force; a non-empty ?role= wins over it.
func TestAdmissionLogin_OperationsEmptyRoleQuery(t *testing.T) {
	e := newJWTEnv(t, "")
	b := e.mount("jwt/", nil)
	grantRole(t, e.c, e.ctx, testGrant{Role: "reader", Policies: []string{"read"}, Mount: "auth/jwt/"})
	token := e.token("agent-1", "")
	withAuth := &namespace.Namespace{
		ID: namespace.RootNamespaceID, Path: "",
		CustomMetadata: map[string]string{"auto_auth_path": "auth/jwt/"},
	}
	ctx := namespace.ContextWithNamespace(context.Background(), withAuth)

	operate := func(target, headerRole string) *logical.Request {
		t.Helper()
		hr := httptest.NewRequest(http.MethodGet, target, nil)
		hr.Header.Set("Authorization", "Bearer "+token)
		if headerRole != "" {
			hr.Header.Set("X-Warden-Role", headerRole)
		}
		req := &logical.Request{Path: "sys/cred/sources", Operation: logical.ReadOperation, HTTPRequest: hr}
		resp, _, _ := e.c.handleNonLoginRequest(ctx, req)
		if resp != nil && resp.Err != nil {
			assert.NotContains(t, resp.Err.Error(), noRoleSelectedOperations, "%s with X-Warden-Role %q", target, headerRole)
		}
		return req
	}

	req := operate("/v1/sys/cred/sources?role=", "reader")
	assert.Equal(t, "reader", req.RequestedRole, "the header selects the role")
	assert.EqualValues(t, 1, b.logins.Load(), "the credential was admitted")

	req = operate("/v1/sys/cred/sources?role=reader", "other")
	assert.Equal(t, "reader", req.RequestedRole, "a non-empty ?role= wins")
}

// The agent leg never admits through a human mount, on either path, before
// any policy runs; flipping the mount to agent admits on the next request.
func TestAdmissionLogin_HumanMountRefusedOnAgentLeg(t *testing.T) {
	e := newJWTEnv(t, "")
	b := e.mount("jwt/", map[string]any{"entity_kind": "human"})
	e.policy("read")
	grantRole(t, e.c, e.ctx, testGrant{Role: "reader", Policies: []string{"read"}, Mount: "auth/jwt/"})
	token := e.token("agent-1", "")

	req, err := e.implicit("jwt/", token, "reader")
	require.ErrorIs(t, err, errHumanMountOnAgentLeg)
	assert.Nil(t, req.TokenEntry(), "refused before the token is set on the request")

	withAuth := &namespace.Namespace{
		ID: namespace.RootNamespaceID, Path: "",
		CustomMetadata: map[string]string{"auto_auth_path": "auth/jwt/"},
	}
	opsCtx := namespace.ContextWithNamespace(context.Background(), withAuth)
	hr := httptest.NewRequest(http.MethodGet, "/v1/sys/cred/sources?role=reader", nil)
	hr.Header.Set("Authorization", "Bearer "+token)
	opsReq := &logical.Request{Path: "sys/cred/sources", Operation: logical.ReadOperation, HTTPRequest: hr}
	resp, _, _ := e.c.handleNonLoginRequest(opsCtx, opsReq)
	require.NotNil(t, resp)
	require.Error(t, resp.Err)
	assert.Equal(t, http.StatusUnauthorized, logical.GetErrorCode(resp.Err))
	assert.Contains(t, resp.Err.Error(), "agent leg cannot admit through a human mount")
	assert.Nil(t, opsReq.TokenEntry())

	// Flip the mount: the cached admission is reused and now admits.
	e.writeConfig(b, map[string]any{"entity_kind": "agent", "bound_audiences": "warden"})
	req, te, err := e.request("jwt/", token, "reader")
	require.NoError(t, err)
	assert.True(t, req.RoleGrant().Granted())
	assert.Equal(t, "reader", te.RoleName)
	assert.EqualValues(t, 1, b.logins.Load(), "the admission cached under the human naming is reused")
}

// A token the issuer minted for another relying party is not admitted by an
// agent mount bound to Warden's audience.
func TestAdmissionLogin_AnotherRelyingPartyRefused(t *testing.T) {
	e := newJWTEnv(t, "")
	e.mount("jwt/", nil)
	grantRole(t, e.c, e.ctx, testGrant{Role: "reader", Policies: []string{"read"}, Mount: "auth/jwt/"})
	token := e.token("agent-1", "another-relying-party")

	req, err := e.implicit("jwt/", token, "reader")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authentication failed")
	assert.Nil(t, req.TokenEntry())
	assert.Nil(t, e.cached("jwt/", token))
}

// An explicit login to a transparent mount is refused, whatever it carries:
// a role in the body selects nothing and no token is issued.
func TestAdmissionLogin_ExplicitLoginRefused(t *testing.T) {
	e := newJWTEnv(t, "")
	e.mount("jwt/", nil)
	token := e.token("agent-1", "")

	resp, _, err := e.c.handleLoginRequest(e.ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "auth/jwt/login",
		Data: map[string]any{"jwt": token, "role": "reader"},
	}, false)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Error(t, resp.Err)
	assert.Contains(t, resp.Err.Error(), "explicit login is not supported")
	assert.Nil(t, e.cached("jwt/", token))
}

// auditCapture records request audit entries.
type auditCapture struct {
	mockAuditManager
	mu       sync.Mutex
	requests []*audit.LogEntry
}

func (m *auditCapture) LogRequest(_ context.Context, e *audit.LogEntry) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests = append(m.requests, e)
	return true, nil
}

// The login's own audit entry names no role, no spec, no metadata and no
// role refusal: a login only admits. The internal login's response carries no
// role either.
func TestAdmissionLogin_AuditCarriesNoRole(t *testing.T) {
	e := newJWTEnv(t, "")
	e.mount("jwt/", map[string]any{"facts": map[string]any{"sub": "sub"}})
	e.policy("read")
	grantRole(t, e.c, e.ctx, testGrant{Role: "reader", Policies: []string{"read"}, Spec: "read-spec", Mount: "auth/jwt/"})
	rec := &auditCapture{}
	e.c.auditManager = rec

	token := e.token("agent-1", "")
	_, _, err := e.request("jwt/", token, "reader")
	require.NoError(t, err)

	var logins int
	for _, entry := range rec.requests {
		if entry.Request == nil || !strings.HasSuffix(entry.Request.Path, "login") {
			continue
		}
		logins++
		raw, err := json.Marshal(entry)
		require.NoError(t, err)
		for _, key := range []string{"role_name", "credential_spec", "read-spec", "role_denied_reason", "role_granted_by", `"metadata"`} {
			assert.NotContains(t, string(raw), key, "login audit entry")
		}
	}
	assert.Equal(t, 1, logins, "the implicit login is audited once")

	resp, _, err := e.c.handleLoginRequest(e.ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "auth/jwt/login",
		Data: map[string]any{"jwt": e.token("agent-2", "")},
	}, true)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotContains(t, resp.Data, "role")
	assert.Nil(t, resp.Auth.Policies)
	assert.Nil(t, resp.Auth.Metadata)
	assert.Equal(t, "agent-2", fmt.Sprint(resp.Data["principal_id"]))
}
