package core

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/audit"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
)

// An access path is its provider's surface for a ticket on either header: the
// role is the provider's, a refusal is 401, and no role is the access path's
// 400.
func TestTicketRequest_AccessPathBothHeaders(t *testing.T) {
	env := newAccessEnv(t, "auth/jwt/")
	e := &ticketEnv{t: t, c: env.c, ns: namespace.RootNamespace, ctx: rootCtx()}
	e.issuer, e.mount = e.mountIssuer(e.ctx, "oidc/")
	grantRole(t, e.c, e.ctx, testGrant{Role: "reader", Policies: []string{"access-reader"}, Mount: "auth/oidc/"})
	value, _ := e.login(e.ctx, e.issuer, e.mount, time.Hour)

	for name, h := range map[string]func(string) map[string]string{"X-Warden-Token": wardenToken, "Authorization": bearer} {
		t.Run(name, func(t *testing.T) {
			resp, req, err := env.get(t, "db/access/ro?role=reader", h(value))
			require.NoError(t, err)
			require.Nil(t, resp.Err)
			assert.Equal(t, "secret-for-ro", resp.Data["secret"])
			assert.True(t, req.TicketAdmitted)

			resp, _, err = env.get(t, "db/access/ro?role=reader", h(value+"x"))
			require.NoError(t, err)
			assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

			resp, _, err = env.get(t, "db/access/ro", h(value))
			require.NoError(t, err)
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			assert.Contains(t, resp.Err.Error(), noRoleSelectedAccess)
		})
	}
}

func TestTicketRequest_GatewayDefaultRole(t *testing.T) {
	e := newTicketRequestEnv(t)
	mountGateway(t, e.c, "defgw/", &ticketGateway{mockTransparentModeProvider{defaultAuthRole: "operator"}})
	_, req, _ := e.do("defgw/gateway/thing", bearer(e.value))
	assert.True(t, req.TicketAdmitted)
	require.NotNil(t, req.RoleGrant())
	assert.Equal(t, "operator", req.RoleGrant().RoleName, "the provider's default_role")
	assert.Equal(t, "group:humans", req.RoleGrant().GrantedBy)
}

// Only X-Warden-Token and the Authorization bearer carry a ticket.
func TestTicketRequest_MisplacedTicketRefused(t *testing.T) {
	e := newTicketRequestEnv(t)
	agentToken := map[string]string{logical.HeaderWardenAgentToken: e.value}

	resp, req, err := e.do("fakegw/role/operator/gateway/thing", agentToken)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Contains(t, resp.Err.Error(), errTicketMisplaced.Error())
	assert.False(t, req.TicketAdmitted)

	resp, _, err = e.do("sys/introspect/roles", agentToken)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestTicketRequest_SiblingNamespaceRefused(t *testing.T) {
	e := newTicketRequestEnv(t)
	a := &namespace.Namespace{Path: "team-a/"}
	b := &namespace.Namespace{Path: "team-b/"}
	require.NoError(t, e.c.namespaceStore.SetNamespace(rootCtx(), a))
	require.NoError(t, e.c.namespaceStore.SetNamespace(rootCtx(), b))
	aCtx := namespace.ContextWithNamespace(context.Background(), a)
	issuer, me := e.mountIssuer(aCtx, "oidc/")
	value, _ := e.login(aCtx, issuer, me, time.Hour)

	for _, cold := range []bool{false, true} {
		if cold {
			e.flushCache()
		}
		hr := httptest.NewRequest(http.MethodGet, "/v1/team-b/sys/providers", nil)
		hr.Header.Set(logical.HeaderWardenToken, value)
		req := &logical.Request{Path: "team-b/sys/providers", Operation: logical.ListOperation, HTTPRequest: hr,
			Data: map[string]any{"role": "operator"}}
		resp, _ := e.c.HandleRequest(context.Background(), req)
		require.NotNil(t, resp)
		assert.Equal(t, http.StatusForbidden, resp.StatusCode, "cold cache %v", cold)
		assert.False(t, req.TicketAdmitted)
	}
}

func TestTicketRequest_ExpiredTicket(t *testing.T) {
	e := newTicketRequestEnv(t)
	p := e.payload()
	p.IssuedAt, p.ExpiresAt = time.Now().Add(-2*time.Hour).Unix(), time.Now().Add(-time.Hour).Unix()
	expired := e.seal(p)

	resp, _, err := e.do("sys/providers?role=operator", wardenToken(expired))
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	resp, _, err = e.do("fakegw/role/operator/gateway/thing", bearer(expired))
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// userLegGateway is a gateway that is a protected resource: Authorization
// carries the user.
type userLegGateway struct {
	ticketGateway
}

func (g *userLegGateway) GetUserAuthPath() string { return "auth/oidc/" }
func (g *userLegGateway) UserAuthRefusal() error  { return nil }

func TestTicketRequest_ProtectedResourceAmbiguity(t *testing.T) {
	e := newTicketRequestEnv(t)
	mountGateway(t, e.c, "prgw/", &userLegGateway{ticketGateway{mockTransparentModeProvider{transparentMode: true}}})
	h := wardenToken(e.value)
	h["Authorization"] = "Bearer eyJ.user.token"
	resp, _, err := e.do("prgw/role/operator/gateway/thing", h)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "the operator and user surfaces stay apart")
}

// An identity token's ID presented explicitly is no credential.
func TestTicketRequest_IdentityTokenIDRefused(t *testing.T) {
	e := newTicketRequestEnv(t)
	te, err := e.c.tokenStore.GenerateToken(e.ctx, TypeIdentityToken, &AuthData{
		TokenValue: "cred", MountAccessor: e.mount.Accessor, ExpireAt: time.Now().Add(time.Hour),
		Admission: &logical.Admission{Mount: e.issuer.mf},
	})
	require.NoError(t, err)
	resp, req, err := e.do("sys/providers?role=operator", wardenToken(te.ID))
	require.Error(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.False(t, req.TicketAdmitted)
}

// An anonymous discovery call with a ticket present runs anonymously, and no
// audit record ever carries the ticket's value.
func TestTicketRequest_AuditNeverCarriesTheValue(t *testing.T) {
	e := newTicketRequestEnv(t)
	srv := startMCPTestServer(t, e.c, nil)
	session := connectMCPWithHeaders(t, srv, wardenToken(e.value))
	_, err := session.ListTools(context.Background(), nil)
	require.NoError(t, err)

	e.audit.mu.Lock()
	var anonymous int
	for _, entry := range e.audit.requests {
		if entry.Request != nil && entry.Request.Path == "mcp" {
			require.NotNil(t, entry.Auth)
			require.NotNil(t, entry.Auth.Discovery)
			assert.True(t, entry.Auth.Discovery.Anonymous)
			assert.Empty(t, entry.Auth.TokenType)
			anonymous++
		}
	}
	e.audit.mu.Unlock()
	assert.NotZero(t, anonymous)

	_, _, err = e.do("sys/providers?role=operator", wardenToken(e.value))
	require.NoError(t, err)
	_, _, err = e.do("sys/introspect/roles", bearer(e.value))
	require.NoError(t, err)

	e.audit.mu.Lock()
	defer e.audit.mu.Unlock()
	for _, entries := range [][]*audit.LogEntry{e.audit.requests, e.audit.responses} {
		for _, entry := range entries {
			b, err := json.Marshal(entry)
			require.NoError(t, err)
			assert.NotContains(t, string(b), e.value[len(ticketValuePrefix):len(ticketValuePrefix)+32])
		}
	}
}
