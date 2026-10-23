package core

import (
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	authhelper "github.com/stephnangue/warden/auth/helper"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/helper/selector"
	"github.com/stephnangue/warden/internal/namespace"
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
	mf     *logical.MountFacts
	claims map[string]any // nil: the credential is not admitted
	err    error          // set: the mount cannot decide
	calls  atomic.Int64   // introspect/admit requests that reached the backend
	admits atomic.Int64   // admission checks run (only for internal requests)

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

func (e *discEnv) role(name, providerPath, skill string) {
	e.t.Helper()
	_, err := e.c.roleStore.Create(e.ctx, &logical.Role{
		Name: name, Description: "the " + name + " role", ProviderPath: providerPath, Skill: skill,
		Policies: []string{"p"},
	})
	require.NoError(e.t, err)
}

func (e *discEnv) group(name string, roles []string, validUntil time.Time, rules ...logical.GroupRule) {
	e.t.Helper()
	_, err := e.c.identityStore.CreateGroup(e.ctx, &logical.Group{
		Name: name, Type: logical.GroupTypeVirtual, Roles: roles, Rules: rules, ValidUntil: validUntil,
	})
	require.NoError(e.t, err)
}

func bearerRequest(bearer string) *logical.Request {
	httpReq := httptest.NewRequest(http.MethodGet, "/v1/sys/introspect/roles", nil)
	if bearer != "" {
		httpReq.Header.Set("Authorization", "Bearer "+bearer)
	}
	return &logical.Request{Operation: logical.ReadOperation, Path: "introspect/roles", HTTPRequest: httpReq}
}

// introspect runs the admission-based sys/introspect/roles handler and returns
// its response, which must succeed.
func (e *discEnv) introspect() *logical.Response {
	e.t.Helper()
	resp, err := e.c.systemBackend.introspectRolesFromAdmissions(e.ctx, bearerRequest("eyJ.any.token"), nil)
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

// listRoles runs the admission-based list_roles resolution for a bearer.
func (e *discEnv) listRoles(bearer string) ([]mcpRole, []string, error) {
	httpReq := httptest.NewRequest(http.MethodPost, "/v1/sys/mcp", nil)
	if bearer != "" {
		httpReq.Header.Set("Authorization", "Bearer "+bearer)
	}
	ctx := withMCPRequest(e.ctx, httpReq)
	return e.c.resolveDiscoveryFromAdmissionsWith(ctx, e.c.discoverySkillChecker(ctx))
}

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
	assert.Equal(t, []admittedRole{{Name: "deploy", Description: "the deploy role", ProviderPath: "vault/"}},
		resp.Data["roles"])
	assert.Equal(t, []string{}, resp.Data["warnings"])
	assert.Equal(t, int64(1), jwt.calls.Load())

	body := e.introspectJSON()
	for _, secret := range []string{"deployers", "outsiders", "repo", "acme", "agent-1", "auth/", "jwt/", "auth_path"} {
		assert.NotContains(t, body, secret)
	}

	roles, warnings, err := e.listRoles("eyJ.any.token")
	require.NoError(t, err)
	assert.Empty(t, warnings)
	assert.Equal(t, []mcpRole{{Name: "deploy", Description: "the deploy role", Provider: "vault",
		URL: "/v1/vault/role/deploy/gateway/"}}, roles)
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
// group pinned to another mount, or a target that does not admit yields.
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
	wantList := ""
	for name, apply := range states {
		t.Run(name, func(t *testing.T) {
			e, m := setup(t)
			apply(t, e, m)
			assert.Equal(t, want, e.introspectJSON())
			list := e.listRolesJSON()
			if wantList == "" {
				wantList = list
			}
			assert.Equal(t, wantList, list)
			assert.Equal(t, int64(2), m.calls.Load(), "the target was asked in every state")
		})
	}
	assert.Equal(t, `{"roles":[],"warnings":[]}`, wantList)

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
	assert.Equal(t, int64(1), m.calls.Load())

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
}

// A target that fails yields today's per-mount warning; the others still list.
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

	_, warnings, err := e.listRoles("eyJ.any.token")
	require.NoError(t, err)
	assert.Equal(t, []string{`mount "jwt-b/": storage unavailable`}, warnings)
}

// No credential is today's 401.
func TestDiscoveryAdmit_NoCredential(t *testing.T) {
	e := newDiscEnv(t, "", "")
	m := e.mountAuth("jwt/")
	e.provider("vault", "vault/", "auth/jwt/")
	e.role("deploy", "vault/", "")

	today, err := e.c.systemBackend.handleIntrospectRoles(e.ctx, &logical.Request{}, nil)
	require.NoError(t, err)
	resp, err := e.c.systemBackend.introspectRolesFromAdmissions(e.ctx, &logical.Request{}, nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Equal(t, today.StatusCode, resp.StatusCode)
	assert.Equal(t, today.Err.Error(), resp.Err.Error())

	_, _, err = e.listRoles("")
	assert.EqualError(t, err, today.Err.Error())
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
	assert.Equal(t, int64(1), m.calls.Load(), "the root-token request reached the mount")
	assert.Zero(t, m.admits.Load(), "and was refused before admitting")
}

// Today's discovery is untouched: it never asks introspect/admit, and it lists
// nothing from groups.
func TestDiscoveryAdmit_LiveAggregatorUntouched(t *testing.T) {
	e := newDiscEnv(t, "", "")
	m := e.mountAuth("jwt/")
	e.provider("vault", "vault/", "auth/jwt/")
	e.role("deploy", "vault/", "")
	e.group("deployers", []string{"deploy"}, time.Time{}, discRule([]string{"auth/jwt/"}, "acme/*"))
	require.Equal(t, []string{"deploy"}, roleNames(e.introspectRoles()))
	m.calls.Store(0)

	resp, err := e.c.systemBackend.handleIntrospectRoles(e.ctx, bearerRequest("eyJ.any.token"), nil)
	require.NoError(t, err)
	assert.Equal(t, []aggregatedRole{}, resp.Data["roles"])
	assert.Equal(t, []string{}, resp.Data["warnings"])

	httpReq := httptest.NewRequest(http.MethodPost, "/v1/sys/mcp", nil)
	httpReq.Header.Set("Authorization", "Bearer eyJ.any.token")
	roles, warnings, err := e.c.resolveDiscovery(withMCPRequest(e.ctx, httpReq))
	require.NoError(t, err)
	assert.Empty(t, roles)
	assert.Empty(t, warnings)
	assert.Zero(t, m.calls.Load())
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
				resp, err := e.c.systemBackend.introspectRolesFromAdmissions(e.ctx, bearerRequest("eyJ.any.token"), nil)
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
