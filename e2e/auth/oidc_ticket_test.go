//go:build e2e

package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/audit"
	h "github.com/stephnangue/warden/e2e/helpers"
)

// People of the identity provider: Ada holds the operator app role, Bob holds
// none, and Big is in 200 groups, too many to fit in a session.
const (
	personAda = "ada@e2e.example"
	personBob = "bob@e2e.example"
	personBig = "big@e2e.example"
)

func oidcPeople() map[string]map[string]any {
	groups := make([]any, 200)
	for i := range groups {
		groups[i] = fmt.Sprintf("%08d-0000-0000-0000-000000000000", i)
	}
	return map[string]map[string]any{
		personAda: {"roles": []any{"Warden.Operator"}},
		personBob: {"roles": []any{}},
		personBig: {"roles": []any{"Warden.Operator"}, "groups": groups},
	}
}

// operators is the rule granting a role to the people holding the operator
// app role.
var operators = h.Rule{"kind": {"human"}, "roles": {"Warden.Operator"}}

// humanEnv is an oidc mount at a fresh path against a fresh identity
// provider, with a role its operators are granted: a policy listing
// providers, in the root namespace and in a child namespace.
type humanEnv struct {
	port  int
	idp   *h.HumanIdP
	mount string // e.g. "oidc-e2e-1a2b3c4d"
	role  string
	child string // a child namespace
}

func newHumanEnv(t *testing.T) *humanEnv {
	t.Helper()
	port := h.GetLeaderPort(t)
	e := &humanEnv{
		port:  port,
		idp:   h.StartHumanIdP(t, oidcPeople()),
		mount: h.UniqueMount("oidc-e2e"),
		role:  h.UniqueMount("e2e-human-operator"),
		child: h.UniqueMount("e2e-oidc-child"),
	}
	h.EnableAuth(t, port, "", e.mount, "oidc", h.OIDCMountConfig(e.idp, nil))
	e.grant(t, e.role, fmt.Sprintf("path \"sys/providers\" {\n  capabilities = [\"list\"]\n}\n"+
		"path \"%s/sys/providers\" {\n  capabilities = [\"list\"]\n}\n", e.child), h.Role{
		Description: "Operators signed in through the e2e identity provider",
	})
	return e
}

// grant writes role with a policy of rules (none when empty) on top of r, and
// grants it to the mount's operators, until the test ends.
func (e *humanEnv) grant(t *testing.T, role, rules string, r h.Role) {
	t.Helper()
	if rules != "" {
		policy := role + "-policy"
		h.MustNS(t, e.port, "", "POST", "sys/policies/cbp/"+policy, h.JSON(t, map[string]any{"policy": rules}))
		t.Cleanup(func() { h.NSRequestBestEffort(e.port, "", "DELETE", "sys/policies/cbp/"+policy) })
		r.Policies = append(r.Policies, policy)
	}
	h.GrantRole(t, e.port, e.mount, role, r, operators)
	t.Cleanup(func() { h.RevokeRoleBestEffort(e.port, e.mount, role) })
}

func (e *humanEnv) login(t *testing.T, home, person string, args ...string) h.LoginRun {
	t.Helper()
	return h.OIDCLogin(t, e.port, home, person, nil, nil, append([]string{"-path=" + e.mount}, args...)...)
}

// asRole selects role on a request.
func asRole(role string) map[string]string { return map[string]string{"X-Warden-Role": role} }

// A person signs in with warden login, gets the role their identity
// provider's app role grants, and every node serves their commands under it.
// The session lives in the ticket alone: nothing reaches the token store.
func TestOIDCLogin_EndToEnd(t *testing.T) {
	e := newHumanEnv(t)
	home := t.TempDir()

	run := e.login(t, home, personAda, "-role="+e.role)
	require.NoError(t, run.Err, run.Stderr)
	assert.Contains(t, run.Stderr, fmt.Sprintf("Using role %q", e.role))
	ticket := h.SessionTicket(t, home)

	// The session is the credential of warden commands against the node it
	// was signed in at (sessions are kept per Warden address)...
	_, stderr, err := h.SessionCLI(t, e.port, home, nil, "list", "sys/providers")
	require.NoError(t, err, stderr)
	// ...and its ticket is accepted through each standby, which forwards it.
	for _, port := range []int{8500, 8510, 8520} {
		status, body := h.TicketRequest(t, "GET", "sys/providers?warden-list=true", port, ticket, asRole(e.role))
		assert.Equal(t, http.StatusOK, status, "node %d: %s", port, body)
	}
	// The role is chosen per request, on X-Warden-Role or on ?role=.
	status, body := h.TicketRequest(t, "GET", "sys/providers?warden-list=true&role="+e.role, e.port, ticket, nil)
	assert.Equal(t, http.StatusOK, status, "?role=: %s", body)

	// Discovery with the ticket, on either header, names the role.
	for _, hdr := range []map[string]string{nil, {"Authorization": "Bearer " + ticket}} {
		var status int
		var body []byte
		if hdr == nil {
			status, body = h.TicketRequest(t, "GET", "sys/introspect/roles", e.port, ticket, nil)
		} else {
			status, body = h.DoRequest(t, "GET", h.NodeURL(e.port)+"/v1/sys/introspect/roles", hdr, "")
		}
		require.Equal(t, http.StatusOK, status, string(body))
		assert.Contains(t, string(body), e.role)
	}

	// The role is granted by a group pinning the mount: core completed the
	// admission with its mount, accessor and alias. The requests above
	// decoded the ticket once and then hit the cache; TestOIDCLogin_Failover
	// decodes it on a node that never saw it.
	status, body = h.TicketRequest(t, "GET", "sys/providers?warden-list=true", e.port, ticket, asRole(e.role))
	require.Equal(t, http.StatusOK, status, string(body))
	// The audit device writes asynchronously: wait for this run's entry.
	var last *audit.LogEntry
	require.Eventually(t, func() bool {
		for _, entry := range h.ReadAuditEntries(t, h.NodeNumberForPort(e.port), e.role) {
			if entry.Type == "request" && entry.Auth != nil && entry.Auth.TokenType == "ticket_token" {
				last = &entry
			}
		}
		return last != nil
	}, 6*time.Second, 200*time.Millisecond, "no audit entry of a ticket request under %s", e.role)
	assert.Equal(t, "ticket_token", last.Auth.TokenType)
	assert.Equal(t, "human", last.Auth.EntityKind)
	assert.Equal(t, personAda, last.Auth.PrincipalID)
	assert.NotEmpty(t, last.Auth.MountAccessor)
	assert.NotZero(t, last.Auth.AuthTime)
	assert.Equal(t, "group:"+h.GrantGroup(e.mount, e.role), last.Auth.RoleGrantedBy)
	assert.False(t, h.GrepNodeLog(t, h.NodeNumberForPort(e.port), ticket[4:40]), "the ticket never reaches a log")

	// No ticket is stored: tokens are kept under core/token/id/ by ID, and a
	// ticket's ID starts with wdt_.
	for _, key := range h.OpenClusterStorage(t).List(t, "core/token/id/") {
		assert.False(t, strings.HasPrefix(key, "wdt_"), "ticket %s is in the token store's storage", key)
	}

	// Signing in again keeps the session.
	run = e.login(t, home, personAda)
	require.NoError(t, run.Err, run.Stderr)
	assert.Contains(t, run.Stderr, "Already signed in")
	assert.Equal(t, ticket, h.SessionTicket(t, home))
}

// warden role use switches the role the session's commands run under, with
// no new login.
func TestOIDCLogin_RoleUse(t *testing.T) {
	e := newHumanEnv(t)
	auditor := h.UniqueMount("e2e-human-auditor")
	e.grant(t, auditor, "path \"sys/policies/cbp\" {\n  capabilities = [\"list\"]\n}\n", h.Role{})
	home := t.TempDir()
	require.NoError(t, e.login(t, home, personAda, "-role="+e.role).Err)
	ticket := h.SessionTicket(t, home)

	_, _, err := h.SessionCLI(t, e.port, home, nil, "list", "sys/policies/cbp")
	require.Error(t, err, "the operator role does not list policies")

	_, stderr, err := h.SessionCLI(t, e.port, home, nil, "role", "use", auditor)
	require.NoError(t, err, stderr)
	assert.Contains(t, stderr, fmt.Sprintf("Using role %q", auditor))
	_, stderr, err = h.SessionCLI(t, e.port, home, nil, "list", "sys/policies/cbp")
	require.NoError(t, err, stderr)
	_, _, err = h.SessionCLI(t, e.port, home, nil, "list", "sys/providers")
	assert.Error(t, err, "the auditor role does not list providers")
	assert.Equal(t, ticket, h.SessionTicket(t, home), "the role is the session's, not the ticket's")
}

// A session's ticket drives a provider's gateway on a role/<r>/ path, and the
// MCP discovery server lists the roles the session can assume.
func TestOIDCLogin_GatewayAndDiscovery(t *testing.T) {
	e := newHumanEnv(t)
	reader := h.UniqueMount("e2e-human-reader")
	e.grant(t, reader, "", h.Role{
		Policies:     []string{"vault-gateway-access"},
		CredSpec:     "vault-token-reader",
		ProviderPath: "vault",
		Description:  "read app secrets through Vault",
	})
	home := t.TempDir()
	require.NoError(t, e.login(t, home, personAda, "-role="+e.role).Err)
	ticket := h.SessionTicket(t, home)

	status, body := h.TicketRequest(t, "GET", "vault/role/"+reader+"/gateway/v1/secret/data/e2e/app-config", e.port, ticket, nil)
	require.Equal(t, http.StatusOK, status, string(body))

	roles := map[string]h.TicketRole{}
	for _, r := range h.TicketListRoles(t, e.port, ticket) {
		roles[r.Name] = r
	}
	require.Contains(t, roles, e.role)
	require.Contains(t, roles, reader)
	assert.Equal(t, "vault", roles[reader].Provider)
	assert.Equal(t, "/v1/vault/role/"+reader+"/gateway/", roles[reader].URL)
}

// A person no group grants a role is signed in and can assume nothing.
func TestOIDCLogin_NoRoleGranted(t *testing.T) {
	e := newHumanEnv(t)
	home := t.TempDir()
	run := e.login(t, home, personBob)
	require.NoError(t, run.Err, run.Stderr)
	assert.Contains(t, run.Stderr, "no group grants you a role")

	_, stderr, err := h.SessionCLI(t, e.port, home, map[string]string{"WARDEN_ROLE": e.role}, "list", "sys/providers")
	assert.Error(t, err)
	assert.Contains(t, stderr, "is not assumable")
	assert.Contains(t, stderr, "no group grants it to this caller")
}

// A session survives a leader change, and a login started before one
// finishes after it: the pending login travels sealed in the state.
func TestOIDCLogin_Failover(t *testing.T) {
	e := newHumanEnv(t)
	home := t.TempDir()
	require.NoError(t, e.login(t, home, personAda, "-role="+e.role).Err)

	ticket := h.SessionTicket(t, home)
	h.StepDown(t, e.port)
	newLeader := h.WaitForLeader(t, 30, time.Second)
	status, body := h.TicketRequest(t, "GET", "sys/providers?warden-list=true", newLeader, ticket, asRole(e.role))
	require.Equal(t, http.StatusOK, status, "the new leader decodes the ticket: %s", body)
	// The node signed in at, now a standby, forwards the session's commands.
	_, stderr, err := h.SessionCLI(t, e.port, home, nil, "list", "sys/providers")
	require.NoError(t, err, stderr)

	// Start a login, fail over before the browser comes back, finish it.
	home2 := t.TempDir()
	run := h.OIDCLogin(t, newLeader, home2, personAda, nil, func() error {
		_, err := h.FailOver(newLeader)
		return err
	}, "-path="+e.mount, "-role="+e.role)
	require.NoError(t, run.Err, run.Stderr)
	h.SessionTicket(t, home2)
	h.AssertClusterHealthy(t)
}

// Disabling the mount ends every session it issued, even once it is enabled
// again; warden login then notices and signs in anew.
func TestOIDCLogin_MountDisableEndsSessions(t *testing.T) {
	e := newHumanEnv(t)
	home := t.TempDir()
	require.NoError(t, e.login(t, home, personAda, "-role="+e.role).Err)
	ticket := h.SessionTicket(t, home)

	// No identity can be claimed on a mount people sign in at, so no claim
	// holds the mount and it is disabled without force.
	status, body := h.APIRequest(t, "POST", "sys/identity/entity/"+h.UniqueMount("e2e-human-claim"), e.port,
		h.JSON(t, map[string]any{"aliases": []map[string]string{{"mount": "auth/" + e.mount + "/", "name": personAda}}}))
	assert.Equal(t, http.StatusBadRequest, status, string(body))
	assert.Contains(t, string(body), "admits human entities")
	path := "sys/auth/" + e.mount
	h.MustNS(t, e.port, "", "DELETE", path, "")
	status, _ = h.TicketRequest(t, "GET", "sys/introspect/roles", e.port, ticket, nil)
	assert.Equal(t, http.StatusUnauthorized, status, "disabled mount")

	h.MustNS(t, e.port, "", "POST", path, `{"type":"oidc"}`)
	h.MustNS(t, e.port, "", "PUT", "auth/"+e.mount+"/config", h.JSON(t, h.OIDCMountConfig(e.idp, nil)))
	status, _ = h.TicketRequest(t, "GET", "sys/introspect/roles", e.port, ticket, nil)
	assert.Equal(t, http.StatusUnauthorized, status, "a mount enabled again is a new accessor")

	run := e.login(t, home, personAda, "-role="+e.role)
	require.NoError(t, run.Err, run.Stderr)
	assert.Contains(t, run.Stderr, "no longer accepted; signing in again")
	assert.NotEqual(t, ticket, h.SessionTicket(t, home))
}

// Deleting a namespace ends the sessions its mounts issued, even once a
// namespace of the same name exists again.
func TestOIDCLogin_NamespaceDeletionEndsSessions(t *testing.T) {
	port := h.GetLeaderPort(t)
	ns := h.UniqueMount("e2e-oidc-ns")
	h.MustNS(t, port, "", "POST", "sys/namespaces/"+ns, "")
	t.Cleanup(func() { h.NSRequestBestEffort(port, "", "DELETE", "sys/namespaces/"+ns) })
	mount, role := h.UniqueMount("oidc-e2e"), h.UniqueMount("e2e-ns-human")
	h.EnableAuth(t, port, ns, mount, "oidc", h.OIDCMountConfig(h.StartHumanIdP(t, oidcPeople()), nil))
	h.GrantRoleInNS(t, port, ns, mount, role, h.Role{}, operators)

	home := t.TempDir()
	run := h.OIDCLogin(t, port, home, personAda, map[string]string{"WARDEN_NAMESPACE": ns}, nil, "-path="+mount, "-role="+role)
	require.NoError(t, run.Err, run.Stderr)
	ticket := h.SessionTicket(t, home)
	inNS := map[string]string{"X-Warden-Namespace": ns}
	status, body := h.TicketRequest(t, "GET", "sys/introspect/roles", port, ticket, inNS)
	require.Equal(t, http.StatusOK, status, string(body))
	assert.Contains(t, string(body), role)

	h.MustNS(t, port, "", "DELETE", "sys/namespaces/"+ns, "")
	require.Eventually(t, func() bool {
		status, _ := h.APIRequest(t, "POST", "sys/namespaces/"+ns, port, "")
		return status == http.StatusCreated
	}, 30*time.Second, time.Second, "namespace %s created again", ns)
	status, _ = h.TicketRequest(t, "GET", "sys/introspect/roles", port, ticket, inNS)
	assert.Equal(t, http.StatusUnauthorized, status)
}

// A session ends at its session_ttl.
func TestOIDCLogin_SessionExpires(t *testing.T) {
	e := newHumanEnv(t)
	h.MustNS(t, e.port, "", "PUT", "auth/"+e.mount+"/config", `{"session_ttl":"6s"}`)
	home := t.TempDir()
	require.NoError(t, e.login(t, home, personAda, "-role="+e.role).Err)
	ticket := h.SessionTicket(t, home)

	status, _ := h.TicketRequest(t, "GET", "sys/providers?warden-list=true", e.port, ticket, asRole(e.role))
	require.Equal(t, http.StatusOK, status)
	require.Eventually(t, func() bool {
		status, _ := h.TicketRequest(t, "GET", "sys/providers?warden-list=true", e.port, ticket, asRole(e.role))
		return status == http.StatusForbidden
	}, 15*time.Second, 250*time.Millisecond, "the ticket is refused once expired")
	_, stderr, _ := h.SessionCLI(t, e.port, home, nil, "list", "sys/providers")
	assert.Contains(t, stderr, "session expired; run warden login")
}

// A parent namespace's session serves its child namespace, under the
// parent's role, whose policy names the child's path.
func TestOIDCLogin_ChildNamespace(t *testing.T) {
	e := newHumanEnv(t)
	h.APIRequest(t, "POST", "sys/namespaces/"+e.child, e.port, "")
	t.Cleanup(func() { h.CleanupNamespaces(t, e.port, e.child) })
	home := t.TempDir()
	require.NoError(t, e.login(t, home, personAda, "-role="+e.role).Err)

	_, stderr, err := h.SessionCLI(t, e.port, home, map[string]string{"WARDEN_NAMESPACE": e.child}, "list", "sys/providers")
	require.NoError(t, err, stderr)
	assert.Contains(t, stderr, "using session from namespace root")
}

func TestOIDCLogin_Refusals(t *testing.T) {
	e := newHumanEnv(t)

	t.Run("a session too large for a ticket is refused at login", func(t *testing.T) {
		run := e.login(t, t.TempDir(), personBig)
		require.Error(t, run.Err)
		assert.Contains(t, run.Stderr, "limit 8000")
	})

	t.Run("an oversized or forged ticket", func(t *testing.T) {
		raw := make([]byte, 96)
		_, _ = rand.Read(raw)
		gateway := "vault/role/e2e-reader/gateway/v1/secret/data/e2e/app-config"
		for name, bad := range map[string]string{
			"oversized": "wdt." + strings.Repeat("A", 9*1024),
			"forged":    "wdt." + base64.RawURLEncoding.EncodeToString(raw),
		} {
			status, _ := h.TicketRequest(t, "GET", "sys/providers?warden-list=true", e.port, bad, asRole(e.role))
			assert.Equal(t, http.StatusForbidden, status, "%s on a sys path", name)
			status, _ = h.TicketRequest(t, "GET", gateway, e.port, bad, nil)
			assert.Equal(t, http.StatusUnauthorized, status, "%s on a gateway", name)
			status, _ = h.TicketRequest(t, "GET", "sys/introspect/roles", e.port, bad, nil)
			assert.Equal(t, http.StatusUnauthorized, status, "%s on discovery", name)
		}
	})

	t.Run("a callback without the login proof", func(t *testing.T) {
		binding := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
		status, body := h.DoRequest(t, "POST", fmt.Sprintf("%s/v1/auth/%s/auth_url", h.NodeURL(e.port), e.mount), nil,
			h.JSON(t, map[string]any{"redirect_uri": "http://localhost:8251/oidc/callback", "login_binding": binding}))
		require.Equal(t, http.StatusOK, status, string(body))
		state := h.JSONString(t, body, "data.state")
		status, body = h.DoRequest(t, "POST", fmt.Sprintf("%s/v1/auth/%s/callback", h.NodeURL(e.port), e.mount), nil,
			h.JSON(t, map[string]any{"state": state, "code": "anything"}))
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Contains(t, string(body), "login_proof does not match")
	})
}
