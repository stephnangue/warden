package core

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
)

// A parent's ticket calling a gateway in a child namespace runs under the
// parent's role, and the role's credential spec is looked up by name in the
// namespace of the request, as for every token of a parent namespace: a spec
// that exists only in the parent is not found.
func TestTicketRequest_ChildGatewayResolvesSpecInRequestNamespace(t *testing.T) {
	e := newTicketRequestEnv(t)
	child := &namespace.Namespace{Path: "team-a/"}
	require.NoError(t, e.c.namespaceStore.SetNamespace(rootCtx(), child))

	p := testParsePolicy(t, `path "team-a/childgw/role/deployer/gateway/*" { capabilities = ["read"] }`)
	p.Name, p.Type = "child-gw", PolicyTypeCBP
	require.NoError(t, e.c.policyStore.SetPolicy(e.ctx, p, nil))
	_, err := e.c.roleStore.Create(e.ctx, &logical.Role{Name: "deployer", Policies: []string{"child-gw"}, CredSpecName: "deploy-spec"})
	require.NoError(t, err)
	_, err = e.c.identityStore.CreateGroup(e.ctx, &logical.Group{
		Name: "deployers", Type: logical.GroupTypeVirtual, Roles: []string{"deployer"},
		Rules: []logical.GroupRule{{"mount": {"auth/oidc/"}}},
	})
	require.NoError(t, err)
	require.NoError(t, e.c.credConfigStore.CreateSource(e.ctx, &credential.CredSource{Name: "src", Type: "local"}))
	require.NoError(t, e.c.credConfigStore.CreateSpec(e.ctx, &credential.CredSpec{
		Name: "deploy-spec", Type: credential.TypeAPIKey, Source: "src",
		Config: credential.NewConfig(map[string]string{"api_key": "k"}),
	}))

	gw := &ticketGateway{mockTransparentModeProvider{transparentMode: true}}
	require.NoError(t, e.c.router.Mount("childgw/", gw, &MountEntry{
		Path: "childgw/", Type: "fake", Class: mountClassProvider, UUID: "childgw-uuid", Accessor: "childgw-acc",
		NamespaceID: child.ID, namespace: child,
	}, &mockBarrierView{prefix: "provider/childgw-uuid/"}))

	hr := httptest.NewRequest(http.MethodGet, "/v1/team-a/childgw/role/deployer/gateway/x", nil)
	hr.Header.Set("Authorization", "Bearer "+e.value)
	req := &logical.Request{Path: "team-a/childgw/role/deployer/gateway/x", Operation: logical.ReadOperation, HTTPRequest: hr}
	resp, _ := e.c.HandleRequest(context.Background(), req)
	assert.True(t, req.TicketAdmitted)
	require.NotNil(t, req.RoleGrant())
	assert.Equal(t, "group:deployers", req.RoleGrant().GrantedBy, "the parent's role is granted in the child")
	require.NotNil(t, resp)
	require.NotNil(t, resp.Err)
	assert.Contains(t, resp.Err.Error(), `credential spec "deploy-spec" not found`,
		"the spec is looked up in the request's namespace, not the role's")
}

// ticketRequestEnv is a ticketEnv with an audit recorder, a role "operator"
// that the group "humans" grants to every human the oidc mount admits with the
// app role Warden.Operator, a role "auditor" no group grants, a gateway at
// fakegw/ and one live ticket.
type ticketRequestEnv struct {
	*ticketEnv
	audit *accessAuditRecorder
	value string
}

func newTicketRequestEnv(t *testing.T) *ticketRequestEnv {
	t.Helper()
	e := &ticketRequestEnv{ticketEnv: newTicketEnv(t), audit: &accessAuditRecorder{}}
	e.c.auditManager = e.audit

	p := testParsePolicy(t, `
path "sys/providers" { capabilities = ["list"] }
path "team-a/sys/providers" { capabilities = ["list"] }
path "fakegw/role/operator/gateway/*" { capabilities = ["read"] }
`)
	p.Name, p.Type = "ops", PolicyTypeCBP
	require.NoError(t, e.c.policyStore.SetPolicy(e.ctx, p, nil))
	for _, r := range []*logical.Role{
		{Name: "operator", Description: "day-to-day operations", Policies: []string{"ops"}},
		{Name: "auditor", Policies: []string{"ops"}},
	} {
		_, err := e.c.roleStore.Create(e.ctx, r)
		require.NoError(t, err)
	}
	_, err := e.c.identityStore.CreateGroup(e.ctx, &logical.Group{
		Name: "humans", Type: logical.GroupTypeVirtual, Roles: []string{"operator"},
		Rules: []logical.GroupRule{{"mount": {"auth/oidc/"}, "kind": {"human"}, "roles": {"Warden.Operator"}}},
	})
	require.NoError(t, err)

	// A transparent gateway whose own auth mount does not exist: a request
	// that reached implicit auth would fail there.
	mountGateway(t, e.c, "fakegw/", &ticketGateway{mockTransparentModeProvider{transparentMode: true, autoAuthPath: "auth/agent-jwt/"}})

	e.value, _ = e.login(e.ctx, e.issuer, e.mount, time.Hour)
	return e
}

// ticketGateway is a streaming gateway that takes its credential as real
// providers do (logical.ExtractTokensDefault).
type ticketGateway struct {
	mockTransparentModeProvider
}

func (g *ticketGateway) SpecialPaths() *logical.Paths {
	return &logical.Paths{Stream: []string{"role/*", "gateway*"}}
}

func (g *ticketGateway) ExtractTokens(r *http.Request, userLeg bool) (string, string) {
	return logical.ExtractTokensDefault(r, userLeg)
}

// do runs path through the request path with headers, as the HTTP layer would:
// a list for sys/providers, a read for anything else. A role query in path is
// parsed as the HTTP layer parses it.
func (e *ticketRequestEnv) do(path string, headers map[string]string) (*logical.Response, *logical.Request, error) {
	e.t.Helper()
	hr := httptest.NewRequest(http.MethodGet, "/v1/"+path, nil)
	for k, v := range headers {
		hr.Header.Set(k, v)
	}
	reqPath, query, _ := strings.Cut(path, "?")
	op := logical.ReadOperation
	if strings.HasSuffix(reqPath, "sys/providers") {
		op = logical.ListOperation
	}
	req := &logical.Request{Path: reqPath, Operation: op, HTTPRequest: hr, RequestID: "req-ticket"}
	if role, ok := strings.CutPrefix(query, "role="); ok {
		req.Data = map[string]any{"role": role}
	}
	resp, err := e.c.HandleRequest(context.Background(), req)
	return resp, req, err
}

func wardenToken(v string) map[string]string { return map[string]string{logical.HeaderWardenToken: v} }

func with(h map[string]string, k, v string) map[string]string {
	h[k] = v
	return h
}

func TestTicketRequest_SysPath(t *testing.T) {
	e := newTicketRequestEnv(t)

	for name, headers := range map[string]map[string]string{
		"X-Warden-Token, ?role=":        wardenToken(e.value),
		"Authorization, ?role=":         bearer(e.value),
		"X-Warden-Token, X-Warden-Role": with(wardenToken(e.value), "X-Warden-Role", "operator"),
	} {
		t.Run(name, func(t *testing.T) {
			path := "sys/providers"
			if !strings.Contains(name, "X-Warden-Role") {
				path += "?role=operator"
			}
			resp, req, err := e.do(path, headers)
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.Nil(t, resp.Err)
			assert.True(t, req.TicketAdmitted)
			assert.False(t, req.Transparent, "a ticket is not transparent mode")
			require.NotNil(t, req.RoleGrant())
			assert.Equal(t, "group:humans", req.RoleGrant().GrantedBy)

			entry := e.audit.requestFor(t, "sys/providers")
			require.NotNil(t, entry.Auth)
			assert.Equal(t, TypeTicketToken, entry.Auth.TokenType)
			assert.Equal(t, "0583-oid", entry.Auth.AliasName)
			assert.Equal(t, "human", entry.Auth.EntityKind)
			assert.Equal(t, "operator", entry.Auth.RoleName)
			assert.Equal(t, e.mount.Accessor, entry.Auth.MountAccessor)
			assert.NotZero(t, entry.Auth.AuthTime)
			assert.Empty(t, entry.Auth.TokenAccessor)
			assert.False(t, entry.Request.Transparent)
		})
	}

	t.Run("no role selected is 400", func(t *testing.T) {
		resp, _, err := e.do("sys/providers", wardenToken(e.value))
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Contains(t, resp.Err.Error(), noRoleSelectedOperations)
	})

	t.Run("a role no group grants is refused", func(t *testing.T) {
		resp, req, err := e.do("sys/providers?role=auditor", wardenToken(e.value))
		require.Error(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		assert.Equal(t, logical.RoleDeniedNotAssumable, req.RoleGrant().DeniedReason)
	})

	t.Run("a bad ticket is 403, on either header", func(t *testing.T) {
		bad := e.value[:len(e.value)-4] + "AAAA"
		for _, h := range []map[string]string{wardenToken(bad), bearer(bad)} {
			resp, req, err := e.do("sys/providers?role=operator", h)
			require.NoError(t, err)
			require.NotNil(t, resp)
			assert.Equal(t, http.StatusForbidden, resp.StatusCode)
			assert.Nil(t, req.TokenEntry())
		}
	})

	t.Run("a bearer ticket is never sent to the namespace's auto_auth_path", func(t *testing.T) {
		ns := namespace.RootNamespace
		ns.CustomMetadata = map[string]string{"auto_auth_path": "auth/agent-jwt/"}
		defer func() { ns.CustomMetadata = nil }()
		resp, req, err := e.do("sys/providers?role=operator", bearer(e.value))
		require.NoError(t, err)
		require.Nil(t, resp.Err)
		assert.True(t, req.TicketAdmitted)
	})
}

// An admission token that is not a ticket still cannot take a role when
// presented explicitly.
func TestTicketRequest_ExplicitAdmissionStillRefused(t *testing.T) {
	e := newTicketRequestEnv(t)
	te, err := e.c.tokenStore.GenerateToken(e.ctx, TypeServiceToken, &AuthData{
		PrincipalID: "agent-1", MountAccessor: e.mount.Accessor, ExpireAt: time.Now().Add(time.Hour),
		Admission: &logical.Admission{Mount: e.issuer.mf},
	})
	require.NoError(t, err)
	_, req, err := e.do("sys/providers?role=operator", wardenToken(te.Data["token"]))
	require.Error(t, err)
	assert.False(t, req.TicketAdmitted)
	assert.Equal(t, logical.RoleDeniedExplicitAdmission, req.RoleGrant().DeniedReason)
}

func TestTicketRequest_Gateway(t *testing.T) {
	e := newTicketRequestEnv(t)

	for name, headers := range map[string]map[string]string{
		"Authorization":  bearer(e.value),
		"X-Warden-Token": wardenToken(e.value),
	} {
		t.Run(name, func(t *testing.T) {
			// Authorized: the request goes on to mint, which fails here only
			// because the test role binds no credential spec.
			resp, req, _ := e.do("fakegw/role/operator/gateway/thing", headers)
			require.NotNil(t, resp)
			require.NotNil(t, resp.Err)
			assert.Contains(t, resp.Err.Error(), "no credential spec is bound to the token")
			assert.True(t, req.TicketAdmitted)
			require.NotNil(t, req.RoleGrant())
			assert.Equal(t, "group:humans", req.RoleGrant().GrantedBy, "the role comes from the URL")
		})
	}

	t.Run("X-Warden-Role overrides the URL", func(t *testing.T) {
		_, req, _ := e.do("fakegw/role/operator/gateway/thing", with(bearer(e.value), "X-Warden-Role", "auditor"))
		require.NotNil(t, req.RoleGrant())
		assert.Equal(t, logical.RoleDeniedNotAssumable, req.RoleGrant().DeniedReason)
	})

	t.Run("no role selected is 400", func(t *testing.T) {
		resp, _, err := e.do("fakegw/gateway/thing", bearer(e.value))
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Contains(t, resp.Err.Error(), noRoleSelectedGateway)
	})

	t.Run("a bad ticket is 401", func(t *testing.T) {
		resp, _, err := e.do("fakegw/role/operator/gateway/thing", bearer(e.value+"x"))
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("the human-mount refusal does not apply", func(t *testing.T) {
		require.Equal(t, logical.EntityKindHuman, e.issuer.mf.Load().Kind)
		_, req, err := e.do("fakegw/role/operator/gateway/thing", bearer(e.value))
		require.NoError(t, err)
		assert.Equal(t, "group:humans", req.RoleGrant().GrantedBy)
	})
}

func TestTicketRequest_AccessPath(t *testing.T) {
	env := newAccessEnv(t, "auth/jwt/")
	e := &ticketEnv{t: t, c: env.c, ns: namespace.RootNamespace, ctx: rootCtx()}
	e.issuer, e.mount = e.mountIssuer(e.ctx, "oidc/")
	grantRole(t, e.c, e.ctx, testGrant{Role: "reader", Policies: []string{"access-reader"}, Mount: "auth/oidc/"})
	value, _ := e.login(e.ctx, e.issuer, e.mount, time.Hour)

	resp, req, err := env.get(t, "db/access/ro?role=reader", bearer(value))
	require.NoError(t, err)
	require.Nil(t, resp.Err)
	assert.Equal(t, "secret-for-ro", resp.Data["secret"])
	assert.Equal(t, "0583-oid", resp.Data["principal"])
	assert.True(t, req.TicketAdmitted)

	resp, _, err = env.get(t, "db/access/ro?role=reader", bearer(value+"x"))
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "401 on a provider's access surface")
}

func TestTicketRequest_Namespaces(t *testing.T) {
	e := newTicketRequestEnv(t)
	child := &namespace.Namespace{Path: "team-a/"}
	require.NoError(t, e.c.namespaceStore.SetNamespace(rootCtx(), child))

	// A root ticket acts in a child under the root's roles.
	hr := httptest.NewRequest(http.MethodGet, "/v1/team-a/sys/providers", nil)
	hr.Header.Set(logical.HeaderWardenToken, e.value)
	req := &logical.Request{Path: "team-a/sys/providers", Operation: logical.ListOperation, HTTPRequest: hr,
		Data: map[string]any{"role": "operator"}}
	_, err := e.c.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, req.TicketAdmitted)
	assert.Equal(t, "group:humans", req.RoleGrant().GrantedBy)

	// A child ticket does not act in the root.
	childCtx := namespace.ContextWithNamespace(context.Background(), child)
	b, me := e.mountIssuer(childCtx, "oidc/")
	childValue, _ := e.login(childCtx, b, me, time.Hour)
	resp, req2, err := e.do("sys/providers?role=operator", wardenToken(childValue))
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Nil(t, req2.TokenEntry())
}

func TestTicketRequest_UserSlotRefused(t *testing.T) {
	e := newTicketRequestEnv(t)
	err := e.c.captureUserContext(e.ctx, &logical.Request{HTTPRequest: httptest.NewRequest(http.MethodGet, "/", nil)},
		"auth/oidc/", nil, e.value)
	assert.ErrorIs(t, err, errTicketInUserSlot)
}

func TestTicketRequest_IntrospectRoles(t *testing.T) {
	e := newTicketRequestEnv(t)
	for name, headers := range map[string]map[string]string{
		"X-Warden-Token": wardenToken(e.value),
		"Authorization":  bearer(e.value),
	} {
		t.Run(name, func(t *testing.T) {
			resp, req, err := e.do("sys/introspect/roles", headers)
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.Nil(t, resp.Err)
			roles := resp.Data["roles"].([]admittedRole)
			require.Len(t, roles, 1)
			assert.Equal(t, "operator", roles[0].Name)
			assert.Equal(t, "day-to-day operations", roles[0].Description)

			assert.False(t, req.TicketAdmitted, "an identity path takes no role")
			require.NotNil(t, req.Discovery)
			require.Len(t, req.Discovery.AdmittedBy, 1)
			assert.Equal(t, "oidc/", req.Discovery.AdmittedBy[0].Mount)
			assert.Equal(t, "0583-oid", req.Discovery.AdmittedBy[0].AliasName)
			assert.Equal(t, 1, req.Discovery.RolesGranted)

			entry := e.audit.requestFor(t, "sys/introspect/roles")
			require.NotNil(t, entry.Auth)
			assert.Equal(t, TypeTicketToken, entry.Auth.TokenType)
			assert.Equal(t, e.mount.Accessor, entry.Auth.MountAccessor, "the issuing mount, though the entry names none")
			assert.Equal(t, "human", entry.Auth.EntityKind)
		})
	}
	assert.Zero(t, e.issuer.requests.Load(), "the issuing mount is never asked to admit")

	t.Run("a bad ticket is 401 with the role-less challenge", func(t *testing.T) {
		for _, h := range []map[string]string{wardenToken(e.value + "x"), bearer(e.value + "x")} {
			resp, _, err := e.do("sys/introspect/roles", h)
			require.NoError(t, err)
			assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
			assert.Equal(t, rolelessChallenge, resp.Headers.Get("WWW-Authenticate"))
		}
	})

	t.Run("an expired ticket is 401", func(t *testing.T) {
		expired := e.seal(func() logical.TicketPayload {
			p := e.payload()
			p.IssuedAt, p.ExpiresAt = time.Now().Add(-2*time.Hour).Unix(), time.Now().Add(-time.Hour).Unix()
			return p
		}())
		resp, _, err := e.do("sys/introspect/roles", wardenToken(expired))
		require.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("discovery from admissions never takes a ticket", func(t *testing.T) {
		_, err := e.c.discoverFromAdmissions(e.ctx, bearerRequest(e.value))
		assert.ErrorIs(t, err, errDiscoveryTicket)
	})
}

func TestTicketRequest_MCPListRoles(t *testing.T) {
	e := newTicketRequestEnv(t)
	srv := startMCPTestServer(t, e.c, nil)
	for name, headers := range map[string]map[string]string{
		"X-Warden-Token": wardenToken(e.value),
		"Authorization":  bearer(e.value),
	} {
		t.Run(name, func(t *testing.T) {
			before := e.c.tokenStore.GetMetrics()
			session := connectMCPWithHeaders(t, srv, headers)
			_, err := session.ListTools(context.Background(), nil)
			require.NoError(t, err)
			mid := e.c.tokenStore.GetMetrics()
			assert.Equal(t, before["tokens_resolved"], mid["tokens_resolved"],
				"an anonymous call decodes no ticket")

			res, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "list_roles"})
			require.NoError(t, err)
			out := decodeListRoles(t, res)
			require.Len(t, out.Roles, 1)
			assert.Equal(t, "operator", out.Roles[0].Name)
		})
	}
	assert.Zero(t, e.issuer.requests.Load())
}
