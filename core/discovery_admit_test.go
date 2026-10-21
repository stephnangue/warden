package core

import (
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"maps"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	authhelper "github.com/stephnangue/warden/auth/helper"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/helper/selector"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/listener"
	"github.com/stephnangue/warden/logical"
)

// admitStub is a controller for auth mounts that serve introspect/admit
// through the real authhelper.AdmitPath, admitting every presented credential
// as fixed claims. Mounts are keyed by the router mount point ("auth/jwt/", or
// "team/auth/jwt/" in a namespace).
type admitStub struct {
	mu     sync.Mutex
	mounts map[string]*admitStubMount
}

type admitStubMount struct {
	mf       *logical.MountFacts
	claims   map[string]any // nil: the credential is not admitted
	err      error          // set: the mount cannot decide
	needCert bool           // admit only a forwarded client certificate
	calls    atomic.Int64   // introspect/admit requests that reached the backend
	admits   atomic.Int64   // admission checks run (only for internal requests)

	mu   sync.Mutex
	made []*logical.Admission // every admission handed out
}

func newAdmitStub() *admitStub { return &admitStub{mounts: map[string]*admitStubMount{}} }

// at returns the mount at mountPoint, creating it as an agent mount mapping
// "repository" to "repo" and admitting the env's claims.
func (s *admitStub) at(t testing.TB, mountPoint string) *admitStubMount {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.mounts[mountPoint]
	if m == nil {
		m = &admitStubMount{mf: &logical.MountFacts{}, claims: discClaims()}
		m.mf.Publish(testNaming(t, "", map[string]string{"repository": "repo"}))
		s.mounts[mountPoint] = m
	}
	return m
}

func (s *admitStub) get(mountPoint string) *admitStubMount {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mounts[mountPoint]
}

func discClaims() map[string]any {
	return map[string]any{"sub": "agent-1", "repository": "acme/infra"}
}

type admitStubBackend struct {
	*framework.Backend
	stub *admitStub
}

func (s *admitStub) factory() logical.Factory {
	return func(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
		b := &admitStubBackend{stub: s}
		b.Backend = &framework.Backend{
			BackendType:  "jwt",
			BackendClass: logical.ClassAuth,
			Paths:        []*framework.Path{authhelper.AdmitPath(b.admit)},
		}
		if err := b.Backend.Setup(ctx, conf); err != nil {
			return nil, err
		}
		return b, nil
	}
}

func (b *admitStubBackend) HandleRequest(ctx context.Context, req *logical.Request) (*logical.Response, error) {
	if m := b.stub.get(req.MountPoint); m != nil && req.Path == authhelper.AdmitPattern {
		m.calls.Add(1)
	}
	return b.Backend.HandleRequest(ctx, req)
}

func (b *admitStubBackend) admit(_ context.Context, req *logical.Request, _ time.Time) (*logical.Admission, error) {
	m := b.stub.get(req.MountPoint)
	if m == nil {
		return nil, nil
	}
	m.admits.Add(1)
	if m.err != nil {
		return nil, m.err
	}
	if m.claims == nil {
		return nil, nil
	}
	if m.needCert && (req.HTTPRequest == nil || listener.ForwardedClientCert(req.HTTPRequest.Context()) == nil) {
		return nil, nil
	}
	adm := &logical.Admission{Facts: selector.NewClaims(maps.Clone(m.claims)), Mount: m.mf}
	m.mu.Lock()
	m.made = append(m.made, adm)
	m.mu.Unlock()
	return adm, nil
}

// discEnv is a core with admitStub auth mounts in one namespace.
type discEnv struct {
	t    *testing.T
	c    *Core
	ns   *namespace.Namespace
	ctx  context.Context
	stub *admitStub
	srv  *httptest.Server // the discovery server, started on first use
}

// newDiscEnv returns an env in the root namespace, or in a new namespace at
// nsPath with auto_auth_path set to autoAuthPath when nsPath is set.
func newDiscEnv(t *testing.T, nsPath, autoAuthPath string) *discEnv {
	t.Helper()
	c := createTestCore(t)
	e := &discEnv{t: t, c: c, ns: namespace.RootNamespace, ctx: rootCtx(), stub: newAdmitStub()}
	if nsPath != "" {
		ns := &namespace.Namespace{Path: nsPath}
		if autoAuthPath != "" {
			ns.CustomMetadata = map[string]string{"auto_auth_path": autoAuthPath}
		}
		require.NoError(t, c.namespaceStore.SetNamespace(rootCtx(), ns))
		e.ns = ns
		e.ctx = namespace.ContextWithNamespace(context.Background(), ns)
	}
	c.authMethods["jwt"] = e.stub.factory()
	return e
}

// mountAuth mounts an admitStub auth mount at path ("jwt/") and returns it.
func (e *discEnv) mountAuth(path string) *admitStubMount {
	e.t.Helper()
	m := e.stub.at(e.t, e.ns.Path+authRoutePrefix+path)
	require.NoError(e.t, e.c.mount(e.ctx, &MountEntry{Class: mountClassAuth, Type: "jwt", Path: path}))
	return m
}

func (e *discEnv) provider(typ, path, autoAuthPath string) {
	e.t.Helper()
	mountDiscoveryProvider(e.t, e.c, e.ctx, typ, path, autoAuthPath, "")
}

// role creates a role described as "the <name> role".
func (e *discEnv) role(name, providerPath, skill string) {
	e.t.Helper()
	e.createRole(&logical.Role{Name: name, Description: "the " + name + " role", ProviderPath: providerPath, Skill: skill})
}

// createRole creates r with a policy.
func (e *discEnv) createRole(r *logical.Role) {
	e.t.Helper()
	r.Policies = []string{"p"}
	_, err := e.c.roleStore.Create(e.ctx, r)
	require.NoError(e.t, err)
}

func (e *discEnv) group(name string, roles []string, validUntil time.Time, rules ...logical.GroupRule) {
	e.t.Helper()
	_, err := e.c.identityStore.CreateGroup(e.ctx, &logical.Group{
		Name: name, Type: logical.GroupTypeVirtual, Roles: roles, Rules: rules, ValidUntil: validUntil,
	})
	require.NoError(e.t, err)
}

// grant creates roles and a group named group granting all of them to every
// credential admitted at the auth mounts listed (router paths, "auth/jwt/").
func (e *discEnv) grant(group string, mounts []string, roles ...*logical.Role) {
	e.t.Helper()
	names := make([]string, len(roles))
	for i, r := range roles {
		e.createRole(r)
		names[i] = r.Name
	}
	e.group(group, names, time.Time{}, discRule(mounts))
}

func bearerRequest(bearer string) *logical.Request {
	httpReq := httptest.NewRequest(http.MethodGet, "/v1/sys/introspect/roles", nil)
	if bearer != "" {
		httpReq.Header.Set("Authorization", "Bearer "+bearer)
	}
	return &logical.Request{Operation: logical.ReadOperation, Path: "introspect/roles", HTTPRequest: httpReq}
}

// introspectAs reads sys/introspect/roles through the request path, in the
// env's namespace, with req's HTTP request.
func (e *discEnv) introspectAs(req *logical.Request) (*logical.Response, error) {
	return e.c.HandleRequest(context.Background(), &logical.Request{
		Operation:   logical.ReadOperation,
		Path:        e.ns.Path + "sys/introspect/roles",
		HTTPRequest: req.HTTPRequest,
	})
}

// introspect reads sys/introspect/roles with a bearer through the request
// path and returns its response, which must succeed.
func (e *discEnv) introspect() *logical.Response {
	e.t.Helper()
	resp, err := e.introspectAs(bearerRequest("eyJ.any.token"))
	require.NoError(e.t, err)
	require.NotNil(e.t, resp)
	require.NoError(e.t, resp.Err)
	return resp
}

// introspectJSON is the encoded body of introspect.
func (e *discEnv) introspectJSON() string {
	e.t.Helper()
	b, err := json.Marshal(e.introspect().Data)
	require.NoError(e.t, err)
	return string(b)
}

func (e *discEnv) introspectRoles() []admittedRole {
	e.t.Helper()
	return e.introspect().Data["roles"].([]admittedRole)
}

// server returns the env's discovery server.
func (e *discEnv) server() *httptest.Server {
	if e.srv == nil {
		e.srv = startMCPTestServer(e.t, e.c, nil)
	}
	return e.srv
}

// headers returns the headers a discovery client in the env's namespace sends
// with bearer.
func (e *discEnv) headers(bearer string) map[string]string {
	return map[string]string{
		"Authorization":      bearerHeader(bearer),
		"X-Warden-Namespace": strings.TrimSuffix(e.ns.Path, "/"),
	}
}

// listRoles calls list_roles on the discovery server with bearer, in the
// env's namespace. A tool error is returned as an error.
func (e *discEnv) listRoles(bearer string) ([]mcpRole, []string, error) {
	e.t.Helper()
	session := connectMCPWithHeaders(e.t, e.server(), e.headers(bearer))
	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "list_roles"})
	require.NoError(e.t, err)
	if res.IsError {
		return nil, nil, errors.New(res.Content[0].(*mcp.TextContent).Text)
	}
	out := decodeListRoles(e.t, res)
	return out.Roles, out.Warnings, nil
}

// listRolesJSON is the encoded structured output of list_roles.
func (e *discEnv) listRolesJSON() string {
	e.t.Helper()
	roles, warnings, err := e.listRoles("eyJ.any.token")
	require.NoError(e.t, err)
	b, err := json.Marshal(listRolesOutput{Roles: roles, Warnings: warnings})
	require.NoError(e.t, err)
	return string(b)
}

func roleNames(roles []admittedRole) []string {
	out := make([]string, len(roles))
	for i, r := range roles {
		out[i] = r.Name
	}
	return out
}

func discRule(mounts []string, repos ...string) logical.GroupRule {
	r := logical.GroupRule{"mount": mounts}
	if len(repos) > 0 {
		r["repo"] = repos
	}
	return r
}

// A role is listed when the target mount admits the credential and a group
// grants the role there; the output names roles only.
func TestDiscoveryAdmit_GrantedRoles(t *testing.T) {
	e := newDiscEnv(t, "", "")
	jwt := e.mountAuth("jwt/")
	e.provider("vault", "vault/", "auth/jwt/")
	e.role("deploy", "vault/", "")
	e.role("other", "vault/", "")
	e.group("deployers", []string{"deploy"}, time.Time{}, discRule([]string{"auth/jwt/"}, "acme/*"))
	e.group("outsiders", []string{"other"}, time.Time{}, discRule([]string{"auth/jwt/"}, "other/*"))

	resp := e.introspect()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, []admittedRole{{Name: "deploy", Description: "the deploy role", ProviderPath: "vault/"}},
		resp.Data["roles"])
	assert.Equal(t, []string{}, resp.Data["warnings"])
	assert.Equal(t, int64(1), jwt.calls.Load())

	body := e.introspectJSON()
	for _, secret := range []string{"deployers", "outsiders", "repo", "acme", "agent-1", "auth/", "jwt/", "auth_path", "admission", "admitted"} {
		assert.NotContains(t, body, secret)
	}

	roles, warnings, err := e.listRoles("eyJ.any.token")
	require.NoError(t, err)
	assert.Empty(t, warnings)
	assert.Equal(t, []mcpRole{{Name: "deploy", Description: "the deploy role", Provider: "vault",
		URL: "/v1/vault/role/deploy/gateway/"}}, roles)
	list := e.listRolesJSON()
	for _, secret := range []string{"deployers", "repo", "acme", "agent-1", "auth/", "auth_path", "admission", "admitted"} {
		assert.NotContains(t, list, secret)
	}
}

// Each distinct target mount admits once per call; a mount no role targets is
// never asked; a role is evaluated at its own target only.
func TestDiscoveryAdmit_OncePerDistinctTarget(t *testing.T) {
	e := newDiscEnv(t, "", "")
	jwt, jwtB, jwtC := e.mountAuth("jwt/"), e.mountAuth("jwt-b/"), e.mountAuth("jwt-c/")
	e.provider("vault", "vault/", "auth/jwt/")
	e.provider("aws", "aws/", "auth/jwt/")
	e.provider("github", "gh/", "auth/jwt-b/")
	for _, r := range [][2]string{{"r-vault", "vault/"}, {"r-vault2", "vault/"}, {"r-aws", "aws/"}, {"r-gh", "gh/"}, {"pinned", "gh/"}} {
		e.role(r[0], r[1], "")
	}
	e.group("all", []string{"r-vault", "r-vault2", "r-aws", "r-gh"}, time.Time{},
		discRule([]string{"auth/jwt/", "auth/jwt-b/"}, "acme/*"))
	// Granted through auth/jwt/ only, but its provider admits through auth/jwt-b/.
	e.group("jwt-only", []string{"pinned"}, time.Time{}, discRule([]string{"auth/jwt/"}))

	assert.Equal(t, []string{"r-aws", "r-gh", "r-vault", "r-vault2"}, roleNames(e.introspectRoles()))
	assert.Equal(t, int64(1), jwt.calls.Load())
	assert.Equal(t, int64(1), jwtB.calls.Load())
	assert.Equal(t, int64(0), jwtC.calls.Load(), "no fan-out to mounts no role targets")
	assert.Equal(t, jwt.calls.Load(), jwt.admits.Load(), "every call was internal")
	assert.Equal(t, jwtB.calls.Load(), jwtB.admits.Load())
}

// An admitted credential matching no group yields byte for byte what a
// namespace with no groups yields, and what a group past its valid_until, a
// group pinned to another mount, or a target that does not admit yields, on
// both live endpoints.
func TestDiscoveryAdmit_NoDisclosure(t *testing.T) {
	setup := func(t *testing.T) (*discEnv, *admitStubMount) {
		e := newDiscEnv(t, "", "")
		m := e.mountAuth("jwt/")
		e.provider("vault", "vault/", "auth/jwt/")
		e.role("deploy", "vault/", "")
		e.role("other", "vault/", "")
		return e, m
	}
	states := map[string]func(t *testing.T, e *discEnv, m *admitStubMount){
		"no groups": func(*testing.T, *discEnv, *admitStubMount) {},
		"groups exist, none match": func(t *testing.T, e *discEnv, _ *admitStubMount) {
			e.group("outsiders", []string{"deploy"}, time.Time{}, discRule([]string{"auth/jwt/"}, "other/*"))
		},
		"group past valid_until": func(t *testing.T, e *discEnv, _ *admitStubMount) {
			e.group("deployers", []string{"deploy"}, time.Now().Add(-time.Minute), discRule([]string{"auth/jwt/"}, "acme/*"))
		},
		"group pinned to another mount": func(t *testing.T, e *discEnv, _ *admitStubMount) {
			e.group("deployers", []string{"deploy"}, time.Time{}, discRule([]string{"auth/elsewhere/"}, "acme/*"))
		},
		"group grants a missing role": func(t *testing.T, e *discEnv, _ *admitStubMount) {
			e.group("deployers", []string{"ghost"}, time.Time{}, discRule([]string{"auth/jwt/"}, "acme/*"))
		},
		"target does not admit": func(t *testing.T, e *discEnv, m *admitStubMount) {
			e.group("deployers", []string{"deploy"}, time.Time{}, discRule([]string{"auth/jwt/"}, "acme/*"))
			m.claims = nil
		},
	}

	const want = `{"roles":[],"warnings":[]}`
	for name, apply := range states {
		t.Run(name, func(t *testing.T) {
			e, m := setup(t)
			apply(t, e, m)
			assert.Equal(t, want, e.introspectJSON())
			assert.Equal(t, want, e.listRolesJSON())
			assert.Equal(t, int64(2), m.calls.Load(), "the target was asked in every state")
		})
	}

	// Control: the same setup with a matching group lists the role.
	e, _ := setup(t)
	e.group("deployers", []string{"deploy"}, time.Time{}, discRule([]string{"auth/jwt/"}, "acme/*"))
	assert.Equal(t, []string{"deploy"}, roleNames(e.introspectRoles()))
}

// A target whose live naming is human grants nothing; flipping it to agent
// grants on the next call.
func TestDiscoveryAdmit_HumanTargetSkipped(t *testing.T) {
	e := newDiscEnv(t, "", "")
	m := e.mountAuth("jwt/")
	m.mf.Publish(testNaming(t, logical.EntityKindHuman, map[string]string{"repository": "repo"}))
	e.provider("vault", "vault/", "auth/jwt/")
	e.role("deploy", "vault/", "")
	e.group("deployers", []string{"deploy"}, time.Time{}, discRule([]string{"auth/jwt/"}, "acme/*"))

	assert.Equal(t, `{"roles":[],"warnings":[]}`, e.introspectJSON())
	assert.Equal(t, `{"roles":[],"warnings":[]}`, e.listRolesJSON())
	assert.Equal(t, int64(2), m.calls.Load())

	m.mf.Publish(testNaming(t, logical.EntityKindAgent, map[string]string{"repository": "repo"}))
	assert.Equal(t, []string{"deploy"}, roleNames(e.introspectRoles()))

	m.mf.Publish(nil)
	assert.Empty(t, e.introspectRoles(), "a mount without a naming answers no fact")
}

// A role without a usable provider is evaluated at the namespace's
// auto_auth_path and listed without a URL; without one it is left out.
func TestDiscoveryAdmit_RolesWithoutProvider(t *testing.T) {
	setup := func(e *discEnv) *admitStubMount {
		m := e.mountAuth("jwt/")
		e.provider("vault", "vault/", "auth/jwt/")
		seedTestSkill(t, e.c, rootCtx(), "gh-repo-creator")
		e.role("recipe", "", "gh-repo-creator")
		e.role("broken", "missing/", "")
		e.role("deploy", "vault/", "")
		e.group("all", []string{"recipe", "broken", "deploy"}, time.Time{}, discRule([]string{"auth/jwt/"}))
		return m
	}

	t.Run("namespace auto_auth_path set", func(t *testing.T) {
		e := newDiscEnv(t, "team/", "auth/jwt/")
		m := setup(e)
		assert.Equal(t, []string{"broken", "deploy", "recipe"}, roleNames(e.introspectRoles()))
		assert.Equal(t, int64(1), m.calls.Load(), "one target: the provider's and the namespace's are the same mount")

		roles, warnings, err := e.listRoles("eyJ.any.token")
		require.NoError(t, err)
		byName := map[string]mcpRole{}
		for _, r := range roles {
			byName[r.Name] = r
		}
		assert.Equal(t, mcpRole{Name: "recipe", Description: "the recipe role", Skill: "skill://gh-repo-creator/SKILL.md"}, byName["recipe"])
		assert.Equal(t, mcpRole{Name: "broken", Description: "the broken role"}, byName["broken"])
		assert.Equal(t, "/v1/team/vault/role/deploy/gateway/", byName["deploy"].URL)
		assert.Equal(t, []string{`role "broken": provider_path "missing/" is not a provider mount in this namespace`}, warnings)
	})

	t.Run("no namespace auto_auth_path", func(t *testing.T) {
		e := newDiscEnv(t, "", "")
		setup(e)
		assert.Equal(t, []string{"deploy"}, roleNames(e.introspectRoles()))
	})

	t.Run("namespace auto_auth_path is its own target", func(t *testing.T) {
		e := newDiscEnv(t, "team/", "auth/jwt-ns/")
		m := setup(e)
		nsMount := e.mountAuth("jwt-ns/")
		// The group pins auth/jwt/ only: roles evaluated at auth/jwt-ns/ are not granted.
		assert.Equal(t, []string{"deploy"}, roleNames(e.introspectRoles()))
		assert.Equal(t, int64(1), m.calls.Load())
		assert.Equal(t, int64(1), nsMount.calls.Load())
	})

	t.Run("namespace auto_auth_path names no auth mount", func(t *testing.T) {
		e := newDiscEnv(t, "team/", "auth/nowhere/")
		setup(e)
		assert.Equal(t, []string{"deploy"}, roleNames(e.introspectRoles()))
	})
}

// list_roles gives a role a URL only when it was granted at its own provider's
// auth mount; a role reached at the namespace's auto_auth_path because its
// provider is unusable is listed without one, with a warning saying why.
func TestDiscoveryAdmit_ListRolesURLDecision(t *testing.T) {
	e := newDiscEnv(t, "team/", "auth/jwt/")
	e.mountAuth("jwt/")
	e.mountAuth("jwt-b/")
	e.provider("vault", "vault/", "auth/jwt/")
	e.provider("github", "github/", "")
	e.provider("slack", "slack/", "auth/jwt")
	e.provider("aws", "aws/", "auth/jwt-b/")
	e.role("served", "vault/", "")
	e.role("no-auto-auth", "github/", "")
	e.role("no-auth-mount", "slack/", "")
	e.role("elsewhere", "aws/", "")
	// One group at the namespace's mount: "elsewhere" is never granted at
	// its provider's mount, so it is not listed at all.
	e.group("all", []string{"served", "no-auto-auth", "no-auth-mount", "elsewhere"}, time.Time{},
		discRule([]string{"auth/jwt/"}))

	roles, warnings, err := e.listRoles("eyJ.any.token")
	require.NoError(t, err)
	assert.Equal(t, []mcpRole{
		{Name: "no-auth-mount", Description: "the no-auth-mount role"},
		{Name: "no-auto-auth", Description: "the no-auto-auth role"},
		{Name: "served", Description: "the served role", Provider: "vault", URL: "/v1/team/vault/role/served/gateway/"},
	}, roles)
	assert.Equal(t, []string{
		`role "no-auth-mount": provider "slack/": auto_auth_path "auth/jwt" names no auth mount`,
		`role "no-auto-auth": provider "github/" has no auto_auth_path, so no role can be used through it`,
	}, warnings)
	assert.NotContains(t, strings.Join(warnings, "\n"), "jwt-b/", "the mount a role was not granted at is never named")
}

// A target that fails yields its per-mount warning and nothing else; the
// others still list.
func TestDiscoveryAdmit_MountFailureWarning(t *testing.T) {
	e := newDiscEnv(t, "", "")
	e.mountAuth("jwt/")
	bad := e.mountAuth("jwt-b/")
	bad.err = errors.New("storage unavailable")
	e.provider("vault", "vault/", "auth/jwt/")
	e.provider("github", "gh/", "auth/jwt-b/")
	e.role("r-vault", "vault/", "")
	e.role("r-gh", "gh/", "")
	e.group("all", []string{"r-vault", "r-gh"}, time.Time{}, discRule([]string{"auth/jwt/", "auth/jwt-b/"}))

	resp := e.introspect()
	assert.Equal(t, []string{"r-vault"}, roleNames(resp.Data["roles"].([]admittedRole)))
	assert.Equal(t, []string{`mount "jwt-b/": storage unavailable`}, resp.Data["warnings"])

	roles, warnings, err := e.listRoles("eyJ.any.token")
	require.NoError(t, err)
	assert.Len(t, roles, 1)
	assert.Equal(t, []string{`mount "jwt-b/": storage unavailable`}, warnings)
}

// No credential is a 401 on sys/introspect/roles and a tool error on
// list_roles, and no mount is asked.
func TestDiscoveryAdmit_NoCredential(t *testing.T) {
	e := newDiscEnv(t, "", "")
	m := e.mountAuth("jwt/")
	e.provider("vault", "vault/", "auth/jwt/")
	e.role("deploy", "vault/", "")

	const msg = "introspection requires a JWT bearer token or TLS client certificate"
	for name, header := range map[string]string{
		"no header":    "",
		"basic auth":   "Basic dXNlcg==",
		"empty bearer": "Bearer ",
	} {
		t.Run(name, func(t *testing.T) {
			req := bearerRequest("")
			if header != "" {
				req.HTTPRequest.Header.Set("Authorization", header)
			}
			resp, err := e.introspectAs(req)
			if err == nil {
				require.NotNil(t, resp)
				assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
				require.Error(t, resp.Err)
				err = resp.Err
			}
			assert.Contains(t, err.Error(), msg)
		})
	}

	_, _, err := e.listRoles("")
	assert.EqualError(t, err, msg)
	assert.Zero(t, m.calls.Load())
}

// introspect/admit is refused through the real request path, root token
// included: the HTTP layer never marks a request internal, and the admission
// check never runs.
func TestDiscoveryAdmit_HTTPCallRefused(t *testing.T) {
	e := newDiscEnv(t, "", "")
	m := e.mountAuth("jwt/")
	rootToken, err := e.c.tokenStore.GenerateRootToken()
	require.NoError(t, err)

	for name, token := range map[string]string{"root token": rootToken, "no token": ""} {
		t.Run(name, func(t *testing.T) {
			httpReq := httptest.NewRequest(http.MethodGet, "/v1/auth/jwt/introspect/admit", nil)
			httpReq.Header.Set("Authorization", "Bearer eyJ.any.token")
			if token != "" {
				httpReq.Header.Set("X-Warden-Token", token)
			}
			resp, err := e.c.HandleRequest(rootCtx(), &logical.Request{
				Path: "auth/jwt/introspect/admit", Operation: logical.ReadOperation, HTTPRequest: httpReq,
			})
			refused := err != nil || (resp != nil && resp.StatusCode == http.StatusForbidden)
			assert.True(t, refused, "status %v, err %v", resp, err)
			if resp != nil {
				assert.NotContains(t, resp.Data, authhelper.AdmissionKey)
			}
		})
	}
	assert.Zero(t, m.admits.Load(), "refused before admitting")
}

// The per-method introspect/roles paths are gone: an auth mount no longer
// serves them.
func TestDiscoveryAdmit_PerMountIntrospectGone(t *testing.T) {
	e := newDiscEnv(t, "", "")
	e.mountAuth("jwt/")
	_, err := e.c.router.Route(e.ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "auth/jwt/introspect/roles", HTTPRequest: bearerRequest("eyJ.any.token").HTTPRequest,
	})
	require.Error(t, err)
}

// postDiscovery POSTs body to the discovery server in the env's namespace with
// bearer, as a client of protocol revision version, and returns the decoded
// JSON-RPC responses (one per call of a batch).
func (e *discEnv) postDiscovery(bearer, version, body string) []map[string]any {
	e.t.Helper()
	req, err := http.NewRequest(http.MethodPost, e.server().URL+"/v1/sys/mcp", strings.NewReader(body))
	require.NoError(e.t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", version)
	for k, v := range e.headers(bearer) {
		if v != "" {
			req.Header.Set(k, v)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(e.t, err)
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(e.t, err)
	require.Equal(e.t, http.StatusOK, resp.StatusCode, "body: %s", raw)
	var out []map[string]any
	if strings.HasPrefix(strings.TrimSpace(string(raw)), "[") {
		require.NoError(e.t, json.Unmarshal(raw, &out), "body: %s", raw)
	} else {
		var one map[string]any
		require.NoError(e.t, json.Unmarshal(raw, &one), "body: %s", raw)
		out = []map[string]any{one}
	}
	return out
}

// One discovery-server request costs at most one admission per distinct
// target mount, however many calls it carries and whether or not the
// credential is admitted: list_roles, skills/list, skills/get, resources/read
// and read_skill in one JSON-RPC batch share one discovery.
func TestDiscoveryAdmit_OneAdmissionPerTargetPerRequest(t *testing.T) {
	e := newDiscEnv(t, "", "")
	jwt, jwtB := e.mountAuth("jwt/"), e.mountAuth("jwt-b/")
	e.provider("vault", "vault/", "auth/jwt/")
	e.provider("github", "gh/", "auth/jwt-b/")
	seedTestSkill(t, e.c, e.ctx, "vault")
	e.role("r-vault", "vault/", "")
	e.role("r-gh", "gh/", "")
	e.group("all", []string{"r-vault", "r-gh"}, time.Time{}, discRule([]string{"auth/jwt/", "auth/jwt-b/"}))

	const batch = `[
		{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_roles","arguments":{}}},
		{"jsonrpc":"2.0","id":2,"method":"skills/list","params":{}},
		{"jsonrpc":"2.0","id":3,"method":"skills/list","params":{}},
		{"jsonrpc":"2.0","id":4,"method":"skills/get","params":{"uri":"skill://vault/SKILL.md"}},
		{"jsonrpc":"2.0","id":5,"method":"resources/read","params":{"uri":"skill://vault/SKILL.md"}},
		{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"read_skill","arguments":{"uri":"skill://vault/SKILL.md"}}}
	]`
	admits := func() (int64, int64) { return jwt.admits.Load(), jwtB.admits.Load() }

	t.Run("admitted credential, one batch", func(t *testing.T) {
		a0, b0 := admits()
		out := e.postDiscovery("eyJ.any.token", "2025-03-26", batch)
		require.Len(t, out, 6)
		for _, r := range out {
			assert.Contains(t, r, "result", "%v", r)
		}
		a1, b1 := admits()
		assert.Equal(t, int64(1), a1-a0)
		assert.Equal(t, int64(1), b1-b0)
	})

	t.Run("one skills/list", func(t *testing.T) {
		session := connectSkillsClient(t, e.server(), "eyJ.any.token")
		a0, b0 := admits()
		assert.Equal(t, []string{"vault"}, skillNames(listSkills(t, session)))
		a1, b1 := admits()
		assert.Equal(t, int64(1), a1-a0)
		assert.Equal(t, int64(1), b1-b0)
	})

	t.Run("credential no target admits, one batch", func(t *testing.T) {
		jwt.claims, jwtB.claims = nil, nil
		defer func() { jwt.claims, jwtB.claims = discClaims(), discClaims() }()
		a0, b0 := admits()
		out := e.postDiscovery("not-a-credential", "2025-03-26", batch)
		require.Len(t, out, 6)
		a1, b1 := admits()
		assert.Equal(t, int64(1), a1-a0, "an unadmitted caller costs no more than one admission per target")
		assert.Equal(t, int64(1), b1-b0)
	})

	t.Run("each request discovers afresh", func(t *testing.T) {
		a0, _ := admits()
		e.postDiscovery("eyJ.any.token", "2025-11-25", `{"jsonrpc":"2.0","id":1,"method":"skills/list","params":{}}`)
		e.postDiscovery("eyJ.any.token", "2025-11-25", `{"jsonrpc":"2.0","id":1,"method":"skills/list","params":{}}`)
		a1, _ := admits()
		assert.Equal(t, int64(2), a1-a0)
	})
}

// Concurrent discovery while groups are published: every call sees one
// snapshot, and no admission's membership cache is ever written (compute, never
// membership). Run with -race.
func TestDiscoveryAdmit_ConcurrentWithPublish(t *testing.T) {
	e := newDiscEnv(t, "", "")
	m := e.mountAuth("jwt/")
	e.provider("vault", "vault/", "auth/jwt/")
	e.role("deploy", "vault/", "")
	e.group("deployers", []string{"deploy"}, time.Time{}, discRule([]string{"auth/jwt/"}, "acme/*"))

	stop := make(chan struct{})
	var publisher sync.WaitGroup
	publisher.Add(1)
	go func() {
		defer publisher.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			repo := "acme/*"
			if i%2 == 1 {
				repo = "other/*"
			}
			_, err := e.c.identityStore.UpdateGroup(e.ctx, &logical.Group{
				Name: "deployers", Type: logical.GroupTypeVirtual, Roles: []string{"deploy"},
				Rules: []logical.GroupRule{discRule([]string{"auth/jwt/"}, repo)},
			}, "")
			assert.NoError(t, err)
		}
	}()

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 25 {
				resp, err := e.introspectAs(bearerRequest("eyJ.any.token"))
				if !assert.NoError(t, err) {
					return
				}
				got := roleNames(resp.Data["roles"].([]admittedRole))
				assert.True(t, len(got) == 0 || reflect.DeepEqual(got, []string{"deploy"}), "%v", got)
			}
		}()
	}
	wg.Wait()
	close(stop)
	publisher.Wait()

	m.mu.Lock()
	defer m.mu.Unlock()
	require.Len(t, m.made, 200)
	for _, adm := range m.made {
		assert.Nil(t, adm.LoadMembership(), "discovery never caches a membership")
		assert.Equal(t, "auth/jwt/", adm.MountPath)
	}
}

// Only core marks a request internal, and only where it routes introspect/admit
// in process: no other package, the HTTP layer included, sets the field.
func TestRequestInternal_OnlyCoreSetsIt(t *testing.T) {
	root, err := filepath.Abs("..")
	require.NoError(t, err)
	fset := token.NewFileSet()
	var writers []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name != "." && (strings.HasPrefix(name, ".") || name == "node_modules" || name == "site") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.KeyValueExpr:
					if id, ok := n.Key.(*ast.Ident); ok && id.Name == "Internal" {
						writers = append(writers, rel+":"+fn.Name.Name)
					}
				case *ast.AssignStmt:
					for _, lhs := range n.Lhs {
						if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == "Internal" {
							writers = append(writers, rel+":"+fn.Name.Name)
						}
					}
				}
				return true
			})
		}
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, []string{filepath.Join("core", "discovery_admit.go") + ":admitAt"}, writers)

	f, ok := reflect.TypeOf(logical.Request{}).FieldByName("Internal")
	require.True(t, ok)
	assert.Equal(t, "-", f.Tag.Get("json"))
}
