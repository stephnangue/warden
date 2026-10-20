package core

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// factsBackend is an auth backend that answers a fixed set of fact names, as a
// fact-mapping auth method does through logical.FactsProvider.
type factsBackend struct {
	typ   string
	names []string
}

var _ logical.FactsProvider = (*factsBackend)(nil)

func (b *factsBackend) FactNames() []string { return b.names }
func (b *factsBackend) HandleRequest(context.Context, *logical.Request) (*logical.Response, error) {
	return nil, nil
}
func (b *factsBackend) Cleanup(context.Context)                             {}
func (b *factsBackend) Setup(context.Context, *logical.BackendConfig) error { return nil }
func (b *factsBackend) Initialize(context.Context) error                    { return nil }
func (b *factsBackend) Config() map[string]any                              { return nil }
func (b *factsBackend) Type() string                                        { return b.typ }
func (b *factsBackend) Class() logical.BackendClass                         { return logical.ClassAuth }
func (b *factsBackend) HandleExistenceCheck(context.Context, *logical.Request) (bool, bool, error) {
	return false, false, nil
}
func (b *factsBackend) SpecialPaths() *logical.Paths { return nil }
func (b *factsBackend) ExtractTokens(*http.Request, bool) (string, string) {
	return "", ""
}

// mountFactsBackend enables an auth mount of method typ at path (relative to
// auth/) whose backend answers names.
func mountFactsBackend(t *testing.T, c *Core, typ, path string, names ...string) {
	t.Helper()
	c.authMethods[typ] = func(context.Context, *logical.BackendConfig) (logical.Backend, error) {
		return &factsBackend{typ: typ, names: names}, nil
	}
	require.NoError(t, c.mount(rootCtx(), &MountEntry{Class: mountClassAuth, Type: typ, Path: path}))
}

func groupRequest(t *testing.T, c *Core, op logical.Operation, path string, data map[string]any) *logical.Response {
	t.Helper()
	return roleRequest(t, c, rootCtx(), op, "identity/"+path, data)
}

// deployersBody is a valid virtual group write.
func deployersBody() map[string]any {
	return map[string]any{
		"type":        "virtual",
		"description": "CI deployers",
		"roles":       []any{"deploy", "read-secrets", "deploy"},
		"selectors": []any{
			map[string]any{
				"mount": []any{"auth/jwt/"},
				"repo":  []any{"acme/*"},
			},
		},
		"max_age":  "10m",
		"metadata": map[string]any{"owner": "platform"},
	}
}

// virtualGroup returns a valid group with one rule.
func virtualGroup(name string, roles ...string) *logical.Group {
	return &logical.Group{
		Name:      name,
		Type:      logical.GroupTypeVirtual,
		Roles:     roles,
		Selectors: []logical.Selector{{"mount": {"auth/jwt/"}, "sub": {"x"}}},
	}
}

func TestGroups_CRUD(t *testing.T) {
	c := createTestCore(t)
	ctx := rootCtx()

	resp := groupRequest(t, c, logical.CreateOperation, "group/deployers", deployersBody())
	require.Equal(t, http.StatusCreated, resp.StatusCode, "%v", resp.Err)
	assert.Equal(t, "deployers", resp.Data["name"])
	assert.Equal(t, "virtual", resp.Data["type"])
	assert.Equal(t, []string{"deploy", "read-secrets"}, resp.Data["roles"], "roles are sorted and deduplicated")
	assert.Equal(t, []map[string][]string{{"mount": {"auth/jwt/"}, "repo": {"acme/*"}}}, resp.Data["selectors"],
		"selectors render as written")
	assert.Equal(t, "10m0s", resp.Data["max_age"])
	assert.Equal(t, map[string]string{"owner": "platform"}, resp.Data["metadata"])
	assert.NotEmpty(t, resp.Data["id"])
	h1, _ := resp.Data["hash"].(string)
	require.NotEmpty(t, h1)
	id := resp.Data["id"]

	resp = groupRequest(t, c, logical.CreateOperation, "group/deployers", deployersBody())
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "a second create of the same name is refused")

	resp = groupRequest(t, c, logical.ReadOperation, "group/deployers", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, h1, resp.Data["hash"])
	assert.Equal(t, "CI deployers", resp.Data["description"])
	created := resp.Data["created_at"].(time.Time)

	// An update replaces what it names and keeps the rest, type included.
	resp = groupRequest(t, c, logical.UpdateOperation, "group/deployers", map[string]any{
		"roles":   []any{},
		"max_age": 0,
	})
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	assert.Equal(t, []string{}, resp.Data["roles"])
	assert.Equal(t, "", resp.Data["max_age"])
	assert.Equal(t, "virtual", resp.Data["type"])
	assert.Equal(t, "CI deployers", resp.Data["description"])
	assert.Equal(t, id, resp.Data["id"], "the ID never changes")
	assert.Equal(t, created, resp.Data["created_at"])
	assert.NotEqual(t, h1, resp.Data["hash"])

	require.Equal(t, http.StatusCreated, groupRequest(t, c, logical.CreateOperation, "group/readers", map[string]any{
		"type":      "virtual",
		"roles":     []any{"read-secrets"},
		"selectors": []any{map[string]any{"mount": []any{"auth/jwt/"}, "sub": []any{"r"}}},
	}).StatusCode)

	resp = groupRequest(t, c, logical.ListOperation, "group", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, []string{"deployers", "readers"}, resp.Data["keys"])
	items := resp.Data["groups"].([]map[string]any)
	require.Len(t, items, 2)
	assert.NotEmpty(t, items[0]["hash"], "a listed group carries its hash")

	resp = groupRequest(t, c, logical.DeleteOperation, "group/deployers", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, http.StatusNotFound, groupRequest(t, c, logical.ReadOperation, "group/deployers", nil).StatusCode)
	assert.Equal(t, http.StatusNotFound, groupRequest(t, c, logical.DeleteOperation, "group/deployers", nil).StatusCode)
	assert.Equal(t, http.StatusNotFound,
		groupRequest(t, c, logical.UpdateOperation, "group/deployers", map[string]any{"description": "x"}).StatusCode)

	// A group handed out is a copy.
	g, _, err := c.identityStore.GetGroup(ctx, "readers")
	require.NoError(t, err)
	g.Roles[0] = "mutated"
	g.Selectors[0]["sub"][0] = "mutated"
	g2, _, err := c.identityStore.GetGroup(ctx, "readers")
	require.NoError(t, err)
	assert.Equal(t, []string{"read-secrets"}, g2.Roles)
	assert.Equal(t, []string{"r"}, g2.Selectors[0]["sub"])
}

func TestGroups_CAS(t *testing.T) {
	c := createTestCore(t)
	ctx := rootCtx()

	resp := groupRequest(t, c, logical.CreateOperation, "group/g", deployersBody())
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	h1 := resp.Data["hash"].(string)

	resp = groupRequest(t, c, logical.UpdateOperation, "group/g", map[string]any{"description": "v2", "expected_hash": h1})
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	h2 := resp.Data["hash"].(string)

	resp = groupRequest(t, c, logical.UpdateOperation, "group/g", map[string]any{"description": "stale", "expected_hash": h1})
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	assert.Contains(t, resp.Err.Error(), "expected_hash no longer matches")
	g, hash, err := c.identityStore.GetGroup(ctx, "g")
	require.NoError(t, err)
	assert.Equal(t, "v2", g.Description)
	assert.Equal(t, h2, hash)

	assert.Equal(t, http.StatusConflict,
		groupRequest(t, c, logical.DeleteOperation, "group/g", map[string]any{"expected_hash": h1}).StatusCode)
	resp = groupRequest(t, c, logical.CreateOperation, "group/fresh", map[string]any{"expected_hash": "x", "type": "virtual"})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "expected_hash means nothing on a create")

	// One retry without expected_hash; a second loss is a 409.
	c.identityStore.beforeGroupUpdate = func() {
		// Land one concurrent write, once.
		c.identityStore.beforeGroupUpdate = nil
		_, err := c.identityStore.UpdateGroup(ctx, virtualGroup("g", "other"), "")
		require.NoError(t, err)
	}
	resp = groupRequest(t, c, logical.UpdateOperation, "group/g", map[string]any{"description": "v3"})
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	g, _, err = c.identityStore.GetGroup(ctx, "g")
	require.NoError(t, err)
	assert.Equal(t, "v3", g.Description, "the retry applied the caller's field")
	assert.Equal(t, []string{"other"}, g.Roles, "on top of the concurrent write")

	inside := false
	c.identityStore.beforeGroupUpdate = func() {
		if inside {
			return
		}
		inside = true
		defer func() { inside = false }()
		_, err := c.identityStore.UpdateGroup(ctx, virtualGroup("g", fmt.Sprint(time.Now().UnixNano())), "")
		require.NoError(t, err)
	}
	t.Cleanup(func() { c.identityStore.beforeGroupUpdate = nil })
	resp = groupRequest(t, c, logical.UpdateOperation, "group/g", map[string]any{"description": "v4"})
	require.Equal(t, http.StatusConflict, resp.StatusCode)
	assert.Contains(t, resp.Err.Error(), `group "g" changed concurrently; read it again and retry`)
}

func TestGroups_Names(t *testing.T) {
	c := createTestCore(t)
	ctx := rootCtx()
	for _, name := range []string{"deployers", "a", "ci-deploy", "ci.v2", "x_1"} {
		_, err := c.identityStore.CreateGroup(ctx, virtualGroup(name))
		assert.NoError(t, err, name)
	}
	for _, name := range []string{"", "-g", "g-", "a/b", "a b", ".x", "é"} {
		_, err := c.identityStore.CreateGroup(ctx, virtualGroup(name))
		assert.Equal(t, http.StatusBadRequest, logical.GetErrorCode(err), "%q must be refused", name)
	}
	_, err := c.systemBackend.HandleRequest(ctx, &logical.Request{Operation: logical.CreateOperation, Path: "identity/group/a/b"})
	assert.Error(t, err, "the path pattern refuses a name with a /")
}

func TestGroups_Type(t *testing.T) {
	c := createTestCore(t)

	body := deployersBody()
	delete(body, "type")
	resp := groupRequest(t, c, logical.CreateOperation, "group/g", body)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, resp.Err.Error(), "type is required")

	for _, typ := range []string{"internal", "directory"} {
		body = deployersBody()
		body["type"] = typ
		resp = groupRequest(t, c, logical.CreateOperation, "group/g", body)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, typ)
		assert.Contains(t, resp.Err.Error(), "not supported yet", typ)
	}
	body = deployersBody()
	body["type"] = "selector"
	resp = groupRequest(t, c, logical.CreateOperation, "group/g", body)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, resp.Err.Error(), "unknown group type")

	for _, f := range []struct {
		name  string
		value any
	}{{"members", []any{"bot"}}, {"link", map[string]any{"directory": "entra"}}} {
		body = deployersBody()
		body[f.name] = f.value
		resp = groupRequest(t, c, logical.CreateOperation, "group/g", body)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, f.name)
		assert.Contains(t, resp.Err.Error(), fmt.Sprintf("%q is not valid on a virtual group", f.name))
	}

	require.Equal(t, http.StatusCreated, groupRequest(t, c, logical.CreateOperation, "group/g", deployersBody()).StatusCode)
	resp = groupRequest(t, c, logical.UpdateOperation, "group/g", map[string]any{"description": "no type"})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "type may be left out on update")
	resp = groupRequest(t, c, logical.UpdateOperation, "group/g", map[string]any{"type": "virtual", "description": "same"})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "the same type may be repeated")
	resp = groupRequest(t, c, logical.UpdateOperation, "group/g", map[string]any{"type": "internal"})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, resp.Err.Error(), "type cannot change; create a new group")
	resp = groupRequest(t, c, logical.UpdateOperation, "group/g", map[string]any{"members": []any{"bot"}})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// The store refuses a type change too.
	g := virtualGroup("g")
	g.Type = logical.GroupTypeInternal
	_, err := c.identityStore.UpdateGroup(rootCtx(), g, "")
	assert.Error(t, err)
}

func TestGroups_Roles(t *testing.T) {
	c := createTestCore(t)
	ctx := rootCtx()

	_, err := c.identityStore.CreateGroup(ctx, virtualGroup("g", "de/ploy"))
	assert.Equal(t, http.StatusBadRequest, logical.GetErrorCode(err), "a role name with a / is refused")
	_, err = c.identityStore.CreateGroup(ctx, virtualGroup("g", ""))
	assert.Equal(t, http.StatusBadRequest, logical.GetErrorCode(err))

	many := make([]string, logical.MaxGroupRoles+1)
	for i := range many {
		many[i] = fmt.Sprintf("r%d", i)
	}
	_, err = c.identityStore.CreateGroup(ctx, virtualGroup("g", many...))
	assert.Equal(t, http.StatusBadRequest, logical.GetErrorCode(err))
	_, err = c.identityStore.CreateGroup(ctx, virtualGroup("g", many[:logical.MaxGroupRoles]...))
	assert.NoError(t, err, "exactly the cap is accepted")

	_, err = c.roleStore.Create(ctx, &logical.Role{Name: "exists"})
	require.NoError(t, err)
	warnings, err := c.identityStore.CreateGroup(ctx, virtualGroup("h", "exists", "missing"))
	require.NoError(t, err, "a missing role is stored")
	assert.Contains(t, warnings, `role "missing" does not exist yet; the group grants it once it does`)
	for _, w := range warnings {
		assert.NotContains(t, w, `"exists"`)
	}
	g, _, err := c.identityStore.GetGroup(ctx, "h")
	require.NoError(t, err)
	assert.Equal(t, []string{"exists", "missing"}, g.Roles)
}

func TestGroups_Selectors(t *testing.T) {
	c := createTestCore(t)
	ctx := rootCtx()

	create := func(selectors ...logical.Selector) ([]string, error) {
		return c.identityStore.CreateGroup(ctx, &logical.Group{
			Name: "g", Type: logical.GroupTypeVirtual, Selectors: selectors,
		})
	}

	_, err := create()
	assert.Equal(t, http.StatusBadRequest, logical.GetErrorCode(err), "a virtual group needs a selector")

	_, err = create(logical.Selector{"mount": {"auth/jwt/"}}, logical.Selector{"sub": {"x"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `selectors[1]: "mount" is required`)

	for _, s := range []logical.Selector{
		{"mount": {"auth/jwt/"}, "Sub": {"x"}},              // bad fact name
		{"mount": {"auth/jwt/"}, "sub": {}},                 // no values
		{"mount": {"auth/jwt/"}, "sub": {""}},               // empty value
		{"mount": {"auth/jwt/"}, "sub": {`x\`}},             // trailing escape
		{"mount": {"auth/jwt/"}, "/x": {"y"}},               // pointer-like name
		{"mount": {strings.Repeat("a", 1025)}},              // value too long
		{"mount": {"auth/jwt/"}, "sub": make([]string, 33)}, // too many values
	} {
		_, err := create(s)
		assert.Equal(t, http.StatusBadRequest, logical.GetErrorCode(err), "%v", s)
	}

	tooMany := make([]logical.Selector, logical.MaxGroupSelectors+1)
	for i := range tooMany {
		tooMany[i] = logical.Selector{"mount": {"auth/jwt/"}, "sub": {fmt.Sprint(i)}}
	}
	_, err = create(tooMany...)
	assert.Equal(t, http.StatusBadRequest, logical.GetErrorCode(err))
	_, err = create(tooMany[:logical.MaxGroupSelectors]...)
	assert.NoError(t, err)

	warnings, err := c.identityStore.CreateGroup(ctx, &logical.Group{
		Name: "any", Type: logical.GroupTypeVirtual,
		Selectors: []logical.Selector{{"mount": {"**"}, "sub": {"x"}}},
	})
	require.NoError(t, err, `"mount": ["**"] is accepted`)
	assert.Contains(t, warnings, `selectors[0]: mount "**" trusts every auth mount in this namespace, including ones enabled later`)

	// Through the API: values must be lists of strings.
	for _, sel := range []any{"x", map[string]any{"mount": "auth/jwt/"}, map[string]any{"mount": []any{1}}} {
		resp := groupRequest(t, c, logical.CreateOperation, "group/api", map[string]any{
			"type": "virtual", "selectors": []any{sel},
		})
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "%v", sel)
	}
}

func TestGroups_FactNameWarnings(t *testing.T) {
	c := createTestCore(t)
	ctx := rootCtx()
	mountFactsBackend(t, c, "jwt", "github-oidc/", "aud", "iss", "repo", "sub")
	mountFactsBackend(t, c, "kubernetes", "k8s/", "aud", "service_account_name", "workload")
	mountFactsBackend(t, c, "cert", "cert/", "ca", "cn", "workload")

	warn := func(g *logical.Group) []string {
		t.Helper()
		g.Name, g.Type = "g", logical.GroupTypeVirtual
		w, err := c.identityStore.CreateGroup(ctx, g)
		require.NoError(t, err)
		require.NoError(t, c.identityStore.DeleteGroup(ctx, "g", ""))
		return w
	}

	// A built-in or mapped name of a listed mount, and mount/kind: no warning.
	assert.Empty(t, warn(&logical.Group{Selectors: []logical.Selector{
		{"mount": {"auth/github-oidc/"}, "repo": {"acme/*"}, "sub": {"x"}, "kind": {"agent"}},
	}}))

	// A name only an unlisted mount produces warns: facts are checked against
	// the rule's own mounts.
	assert.Equal(t, []string{
		`selectors[0]: no auth mount the rule lists produces fact "workload"; the rule cannot match until one maps it`,
	}, warn(&logical.Group{Selectors: []logical.Selector{
		{"mount": {"auth/github-oidc/"}, "workload": {"x"}},
	}}))

	// Listing both mounts: one of them produces it.
	assert.Empty(t, warn(&logical.Group{Selectors: []logical.Selector{
		{"mount": {"auth/github-oidc/", "auth/k8s/"}, "workload": {"x"}},
	}}))

	// A glob that lists both reaches them too.
	assert.Empty(t, warn(&logical.Group{Selectors: []logical.Selector{
		{"mount": {"auth/*/"}, "workload": {"x"}, "repo": {"y"}},
	}}))

	// A literal mount naming no mount warns; facts are then not checked.
	assert.Equal(t, []string{
		`selectors[0]: mount "auth/gone/" names no auth mount in this namespace; the rule cannot match through it until one is enabled there`,
	}, warn(&logical.Group{Selectors: []logical.Selector{{"mount": {"auth/gone/"}, "email": {"x"}}}}))
	assert.Equal(t, []string{
		`selectors[0]: no auth mount in this namespace matches the rule's mount patterns`,
	}, warn(&logical.Group{Selectors: []logical.Selector{{"mount": {"auth/zz-*/"}, "email": {"x"}}}}))

	// An unknown kind never matches.
	assert.Contains(t, warn(&logical.Group{Selectors: []logical.Selector{
		{"mount": {"auth/k8s/"}, "kind": {"robot"}},
	}}), `selectors[0]: kind "robot" is neither "agent" nor "human" and never matches`)

	// max_age on a rule that lists only cert mounts warns; with a mount that
	// carries an issue time it does not.
	assert.Equal(t, []string{
		`selectors[0]: max_age never matches this rule: its mounts (auth/cert/) admit credentials that carry no issue time`,
	}, warn(&logical.Group{MaxAge: time.Minute, Selectors: []logical.Selector{
		{"mount": {"auth/cert/"}, "cn": {"x"}},
	}}))
	assert.Empty(t, warn(&logical.Group{MaxAge: time.Minute, Selectors: []logical.Selector{
		{"mount": {"auth/cert/", "auth/k8s/"}, "workload": {"x"}},
	}}))

	// Warnings are indexed by rule.
	w := warn(&logical.Group{Selectors: []logical.Selector{
		{"mount": {"auth/k8s/"}, "workload": {"x"}},
		{"mount": {"auth/k8s/"}, "repo": {"x"}},
	}})
	assert.Equal(t, []string{
		`selectors[1]: no auth mount the rule lists produces fact "repo"; the rule cannot match until one maps it`,
	}, w)
}

func TestGroups_Caps(t *testing.T) {
	c := createTestCore(t)
	ctx := rootCtx()

	g := virtualGroup("d")
	g.Description = strings.Repeat("x", logical.MaxGroupDescriptionBytes)
	_, err := c.identityStore.CreateGroup(ctx, g)
	assert.NoError(t, err)
	g = virtualGroup("d2")
	g.Description = strings.Repeat("x", logical.MaxGroupDescriptionBytes+1)
	_, err = c.identityStore.CreateGroup(ctx, g)
	assert.Equal(t, http.StatusBadRequest, logical.GetErrorCode(err))

	g = virtualGroup("m")
	g.Metadata = map[string]string{"": "v"}
	_, err = c.identityStore.CreateGroup(ctx, g)
	assert.Equal(t, http.StatusBadRequest, logical.GetErrorCode(err))
	g = virtualGroup("m")
	g.MaxAge = -time.Second
	_, err = c.identityStore.CreateGroup(ctx, g)
	assert.Equal(t, http.StatusBadRequest, logical.GetErrorCode(err))

	// The namespace caps, lowered for the test.
	other := namespace.ContextWithNamespace(context.Background(),
		&namespace.Namespace{ID: "caps-ns", UUID: "caps-ns-uuid", Path: "caps/"})
	c.identityStore.mu.Lock()
	c.identityStore.maxGroups, c.identityStore.maxSelectors = 3, 4
	c.identityStore.mu.Unlock()

	for _, n := range []string{"a", "b", "c"} {
		_, err := c.identityStore.CreateGroup(other, virtualGroup(n))
		require.NoError(t, err)
	}
	_, err = c.identityStore.CreateGroup(other, virtualGroup("d"))
	assert.ErrorIs(t, err, ErrTooManyGroups)
	resp := roleRequest(t, c, other, logical.CreateOperation, "identity/group/d", deployersBody())
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, resp.Err.Error(), "at most 3 groups")

	two := virtualGroup("a")
	two.Selectors = append(two.Selectors, logical.Selector{"mount": {"auth/jwt/"}, "sub": {"y"}})
	_, err = c.identityStore.UpdateGroup(other, two, "")
	require.NoError(t, err, "3 groups, 4 selectors: at the cap")
	three := virtualGroup("b")
	three.Selectors = append(three.Selectors, logical.Selector{"mount": {"auth/jwt/"}, "sub": {"z"}})
	_, err = c.identityStore.UpdateGroup(other, three, "")
	assert.ErrorIs(t, err, ErrTooManySelectors, "an update counts the selectors it replaces and adds")
	require.NoError(t, c.identityStore.DeleteGroup(other, "c", ""))
	_, err = c.identityStore.CreateGroup(other, two.Clone())
	assert.ErrorIs(t, err, ErrGroupAlreadyExists)
	g = virtualGroup("e")
	g.Selectors = append(g.Selectors, logical.Selector{"mount": {"auth/jwt/"}, "sub": {"y"}})
	_, err = c.identityStore.CreateGroup(other, g)
	assert.ErrorIs(t, err, ErrTooManySelectors, "a create counts its selectors")
}

// TestGroups_RoleFilterAndHTTP drives the paths through the request path:
// LIST ?role= and DELETE ?expected_hash= reach the handlers, and the token is
// checked.
func TestGroups_RoleFilterAndHTTP(t *testing.T) {
	c := createTestCore(t)
	root, err := c.tokenStore.GenerateRootToken()
	require.NoError(t, err)

	resp := roleHTTP(t, c, root, http.MethodPost, "/v1/sys/identity/group/deployers", deployersBody())
	require.Equal(t, http.StatusCreated, resp.StatusCode, "%v", resp.Err)
	hash := resp.Data["hash"].(string)
	resp = roleHTTP(t, c, root, http.MethodPost, "/v1/sys/identity/group/readers", map[string]any{
		"type":      "virtual",
		"roles":     []string{"read-secrets"},
		"selectors": []any{map[string]any{"mount": []string{"auth/jwt/"}, "sub": []string{"r"}}},
	})
	require.Equal(t, http.StatusCreated, resp.StatusCode, "%v", resp.Err)

	resp = roleHTTP(t, c, root, http.MethodGet, "/v1/sys/identity/group?warden-list=true&role=deploy", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	assert.Equal(t, []string{"deployers"}, resp.Data["keys"])
	resp = roleHTTP(t, c, root, http.MethodGet, "/v1/sys/identity/group?warden-list=true&role=read-secrets", nil)
	assert.Equal(t, []string{"deployers", "readers"}, resp.Data["keys"])
	resp = roleHTTP(t, c, root, http.MethodGet, "/v1/sys/identity/group?warden-list=true&role=nobody", nil)
	assert.Equal(t, []string{}, resp.Data["keys"])
	resp = roleHTTP(t, c, root, http.MethodGet, "/v1/sys/identity/group?warden-list=true", nil)
	assert.Equal(t, []string{"deployers", "readers"}, resp.Data["keys"])

	resp = roleHTTP(t, c, root, http.MethodDelete, "/v1/sys/identity/group/deployers?expected_hash=stale", nil)
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	resp = roleHTTP(t, c, root, http.MethodDelete, "/v1/sys/identity/group/deployers?expected_hash="+hash, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	_, _, err = c.identityStore.GetGroup(rootCtx(), "deployers")
	assert.ErrorIs(t, err, ErrGroupNotFound)
}

func TestGroups_SudoRequired(t *testing.T) {
	c := createTestCore(t)
	ctx := rootCtx()

	for _, p := range []string{"sys/identity/group", "sys/identity/group/", "sys/identity/group/deployers"} {
		assert.True(t, c.router.RootPath(ctx, p), "%s must require sudo", p)
	}
	for _, tc := range []struct {
		op   logical.Operation
		path string
	}{
		{logical.CreateOperation, "sys/identity/group/g"},
		{logical.ReadOperation, "sys/identity/group/g"},
		{logical.UpdateOperation, "sys/identity/group/g"},
		{logical.DeleteOperation, "sys/identity/group/g"},
		{logical.ListOperation, "sys/identity/group"},
	} {
		req := &logical.Request{Operation: tc.op, Path: tc.path}
		noSudo, err := NewCBP(ctx, []*Policy{testParsePolicy(t,
			`path "sys/identity/group" { capabilities = ["list"] }
			 path "sys/identity/group/*" { capabilities = ["create", "read", "update", "delete", "list"] }`)})
		require.NoError(t, err)
		res := c.performPolicyChecks(ctx, noSudo, nil, req, &PolicyCheckOpts{RootPrivsRequired: c.router.RootPath(ctx, tc.path)})
		assert.False(t, res.Allowed, "%s %s without sudo must be refused", tc.op, tc.path)

		withSudo, err := NewCBP(ctx, []*Policy{testParsePolicy(t,
			`path "sys/identity/group" { capabilities = ["list", "sudo"] }
			 path "sys/identity/group/*" { capabilities = ["create", "read", "update", "delete", "list", "sudo"] }`)})
		require.NoError(t, err)
		res = c.performPolicyChecks(ctx, withSudo, nil, req, &PolicyCheckOpts{RootPrivsRequired: c.router.RootPath(ctx, tc.path)})
		assert.True(t, res.Allowed, "%s %s with sudo must be allowed", tc.op, tc.path)
	}
}

// TestRoles_DeleteWarnsNamingGroups: deleting a role that groups list succeeds,
// keeps the groups' entries and names the groups in a warning.
func TestRoles_DeleteWarnsNamingGroups(t *testing.T) {
	c := createTestCore(t)
	ctx := rootCtx()
	_, err := c.roleStore.Create(ctx, &logical.Role{Name: "deploy"})
	require.NoError(t, err)
	_, err = c.roleStore.Create(ctx, &logical.Role{Name: "lonely"})
	require.NoError(t, err)
	for _, n := range []string{"ci", "admins"} {
		_, err := c.identityStore.CreateGroup(ctx, virtualGroup(n, "deploy"))
		require.NoError(t, err)
	}

	resp := roleRequest(t, c, ctx, logical.DeleteOperation, "roles/deploy", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, []string{`groups still list "deploy": admins, ci (they grant nothing until the role is re-created)`},
		respWarnings(resp))
	g, _, err := c.identityStore.GetGroup(ctx, "ci")
	require.NoError(t, err)
	assert.Equal(t, []string{"deploy"}, g.Roles, "the group keeps the entry")

	resp = roleRequest(t, c, ctx, logical.DeleteOperation, "roles/lonely", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Empty(t, respWarnings(resp))
}

// TestGroups_LoadFromStorage covers a restart: groups are rebuilt and compiled
// from storage, unreadable and orphaned records are skipped, and a record whose
// name another record holds is skipped.
func TestGroups_LoadFromStorage(t *testing.T) {
	c := createTestCore(t)
	ctx := rootCtx()

	_, err := c.identityStore.CreateGroup(ctx, virtualGroup("deployers", "deploy"))
	require.NoError(t, err)
	want, wantHash, err := c.identityStore.GetGroup(ctx, "deployers")
	require.NoError(t, err)

	view := c.identityStore.storage
	require.NoError(t, view.Put(ctx, &sdklogical.StorageEntry{Key: groupStorageKey(namespace.RootNamespaceUUID, "broken"), Value: []byte("{")}))
	require.NoError(t, view.Put(ctx, &sdklogical.StorageEntry{Key: groupStorageKey("gone-ns-uuid", "x"), Value: []byte(`{"version":1}`)}))
	dup := want.Clone()
	dup.ID = "zz-dup"
	raw := `{"version":1,"group":{"id":"zz-dup","name":"deployers","type":"virtual","roles":["other"],"selectors":[{"mount":["auth/jwt/"],"sub":["x"]}]}}`
	require.NoError(t, view.Put(ctx, &sdklogical.StorageEntry{Key: groupStorageKey(namespace.RootNamespaceUUID, dup.ID), Value: []byte(raw)}))

	c.teardownIdentityStore()
	_, _, err = c.identityStore.GetGroup(ctx, "deployers")
	assert.ErrorIs(t, err, ErrGroupNotFound, "an unloaded store serves nothing")
	assert.Same(t, emptyNSGroups, c.identityStore.namespaceGroups(namespace.RootNamespaceID))
	_, err = c.identityStore.CreateGroup(ctx, virtualGroup("x"))
	assert.ErrorIs(t, err, ErrIdentityStoreNotLoaded)

	require.NoError(t, c.setupIdentityStore(ctx, false))
	got, hash, err := c.identityStore.GetGroup(ctx, "deployers")
	require.NoError(t, err)
	assert.Equal(t, want.ID, got.ID, "the first record by ID keeps the name")
	assert.Equal(t, wantHash, hash)
	gs := c.identityStore.namespaceGroups(namespace.RootNamespaceID)
	require.Len(t, gs.selecting, 1)
	assert.NotEmpty(t, gs.selecting[0].rules, "loaded groups are compiled")

	c.teardownIdentityStore()
	require.NoError(t, c.setupIdentityStore(ctx, true))
	_, _, err = c.identityStore.GetGroup(ctx, "deployers")
	assert.ErrorIs(t, err, ErrGroupNotFound, "a standby loads nothing")
}

// TestGroups_LoadActiveOnly: groups load on the active node only, and a
// failover rebuilds them on the new active node.
func TestGroups_LoadActiveOnly(t *testing.T) {
	origSleep := manualStepDownSleepPeriod
	manualStepDownSleepPeriod = 100 * time.Millisecond
	defer func() { manualStepDownSleepPeriod = origSleep }()

	active, standby, core1, core2, _ := setupTwoNodeHA(t)
	defer core1.Shutdown()
	defer core2.Shutdown()
	ctx := rootCtx()

	_, err := active.identityStore.CreateGroup(ctx, virtualGroup("deployers", "deploy"))
	require.NoError(t, err)
	_, _, err = standby.identityStore.GetGroup(ctx, "deployers")
	assert.ErrorIs(t, err, ErrGroupNotFound, "a standby holds no groups")
	_, err = standby.identityStore.CreateGroup(ctx, virtualGroup("other"))
	assert.ErrorIs(t, err, ErrIdentityStoreNotLoaded, "a standby takes no group writes")

	require.NoError(t, active.StepDown(nil))
	promoted := waitForActiveNode(t, []*Core{standby}, 10*time.Second)
	require.Same(t, standby, promoted)
	require.Eventually(t, func() bool {
		g, _, err := promoted.identityStore.GetGroup(ctx, "deployers")
		return err == nil && len(g.Roles) == 1
	}, 5*time.Second, 20*time.Millisecond, "the new active node loads the groups")
	require.Eventually(t, func() bool {
		_, _, err := active.identityStore.GetGroup(ctx, "deployers")
		return err != nil
	}, 5*time.Second, 20*time.Millisecond, "the node that stepped down drops its snapshot")
}

func TestGroups_ClearNamespace(t *testing.T) {
	c := createTestCore(t)
	child := &namespace.Namespace{ID: "clear-ns", UUID: "clear-ns-uuid", Path: "clear/"}
	childCtx := namespace.ContextWithNamespace(context.Background(), child)

	for _, n := range []string{"a", "b"} {
		_, err := c.identityStore.CreateGroup(childCtx, virtualGroup(n))
		require.NoError(t, err)
	}
	_, err := c.identityStore.CreateGroup(rootCtx(), virtualGroup("keep"))
	require.NoError(t, err)
	rootGS := c.identityStore.namespaceGroups(namespace.RootNamespaceID)

	require.NoError(t, c.namespaceStore.clearNamespaceResources(childCtx, child))

	groups, _, err := c.identityStore.ListGroups(childCtx, "")
	require.NoError(t, err)
	assert.Empty(t, groups)
	assert.Same(t, emptyNSGroups, c.identityStore.namespaceGroups(child.ID))
	keys, err := c.identityStore.storage.List(context.Background(), groupListPrefix(child.UUID))
	require.NoError(t, err)
	assert.Empty(t, keys, "the namespace's records are deleted from storage")
	assert.Same(t, rootGS, c.identityStore.namespaceGroups(namespace.RootNamespaceID), "other namespaces are untouched")
}
