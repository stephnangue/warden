package core

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
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
	kind  string // "" answers agent

	// aliasSource is the fact aliases are taken from; a config write's
	// alias_name_source replaces it in AliasChange's answer.
	aliasSource string
}

var _ logical.FactsProvider = (*factsBackend)(nil)

func (b *factsBackend) FactNames() []string { return b.names }
func (b *factsBackend) AliasChange(data map[string]any) (string, string) {
	if b.aliasSource == "" {
		return "", ""
	}
	next, sent := data["alias_name_source"].(string)
	if !sent {
		next = b.aliasSource
	}
	return "from " + b.aliasSource, "from " + next
}
func (b *factsBackend) EntityKind() string {
	if b.kind == "" {
		return logical.EntityKindAgent
	}
	return b.kind
}
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
		"rules": []any{
			map[string]any{
				"mount": []any{"auth/jwt/"},
				"repo":  []any{"acme/*"},
			},
		},
		"valid_until": "2099-12-31T23:59:59+02:00",
		"metadata":    map[string]any{"owner": "platform"},
	}
}

// virtualGroup returns a valid group with one rule.
func virtualGroup(name string, roles ...string) *logical.Group {
	return &logical.Group{
		Name:  name,
		Type:  logical.GroupTypeVirtual,
		Roles: roles,
		Rules: []logical.GroupRule{{"mount": {"auth/jwt/"}, "sub": {"x"}}},
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
	assert.Equal(t, []map[string][]string{{"mount": {"auth/jwt/"}, "repo": {"acme/*"}}}, resp.Data["rules"],
		"rules render as written")
	assert.Equal(t, 1, resp.Data["rule_count"])
	assert.Equal(t, 2, resp.Data["selector_count"], "mount and repo")
	assert.Equal(t, "2099-12-31T21:59:59Z", resp.Data["valid_until"], "stored and rendered as the same instant in UTC")
	assert.NotContains(t, resp.Data, "max_age")
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

	// An update replaces what it names and keeps the rest.
	resp = groupRequest(t, c, logical.UpdateOperation, "group/deployers", map[string]any{
		"type":        "virtual",
		"roles":       []any{},
		"valid_until": "",
	})
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	assert.Equal(t, []string{}, resp.Data["roles"])
	assert.Equal(t, "", resp.Data["valid_until"], "an empty valid_until clears it")
	assert.Equal(t, "virtual", resp.Data["type"])
	assert.Equal(t, "CI deployers", resp.Data["description"])
	assert.Equal(t, id, resp.Data["id"], "the ID never changes")
	assert.Equal(t, created, resp.Data["created_at"])
	assert.NotEqual(t, h1, resp.Data["hash"])

	require.Equal(t, http.StatusCreated, groupRequest(t, c, logical.CreateOperation, "group/readers", map[string]any{
		"type":  "virtual",
		"roles": []any{"read-secrets"},
		"rules": []any{map[string]any{"mount": []any{"auth/jwt/"}, "sub": []any{"r"}}},
	}).StatusCode)

	resp = groupRequest(t, c, logical.ListOperation, "group", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, []string{"deployers", "readers"}, resp.Data["keys"])
	items := resp.Data["groups"].([]map[string]any)
	require.Len(t, items, 2)
	assert.NotEmpty(t, items[0]["hash"], "a listed group carries its hash")

	resp = groupRequest(t, c, logical.DeleteOperation, "group/deployers", virtualType())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, http.StatusNotFound, groupRequest(t, c, logical.ReadOperation, "group/deployers", nil).StatusCode)
	assert.Equal(t, http.StatusNotFound, groupRequest(t, c, logical.DeleteOperation, "group/deployers", virtualType()).StatusCode)
	assert.Equal(t, http.StatusNotFound,
		groupRequest(t, c, logical.UpdateOperation, "group/deployers", map[string]any{"type": "virtual", "description": "x"}).StatusCode)

	// A group handed out is a copy.
	g, _, err := c.identityStore.GetGroup(ctx, "readers")
	require.NoError(t, err)
	g.Roles[0] = "mutated"
	g.Rules[0]["sub"][0] = "mutated"
	g2, _, err := c.identityStore.GetGroup(ctx, "readers")
	require.NoError(t, err)
	assert.Equal(t, []string{"read-secrets"}, g2.Roles)
	assert.Equal(t, []string{"r"}, g2.Rules[0]["sub"])
}

func TestGroups_CAS(t *testing.T) {
	c := createTestCore(t)
	ctx := rootCtx()

	resp := groupRequest(t, c, logical.CreateOperation, "group/g", deployersBody())
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	h1 := resp.Data["hash"].(string)

	resp = groupRequest(t, c, logical.UpdateOperation, "group/g", map[string]any{"type": "virtual", "description": "v2", "expected_hash": h1})
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	h2 := resp.Data["hash"].(string)

	resp = groupRequest(t, c, logical.UpdateOperation, "group/g", map[string]any{"type": "virtual", "description": "stale", "expected_hash": h1})
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	assert.Contains(t, resp.Err.Error(), "expected_hash no longer matches")
	g, hash, err := c.identityStore.GetGroup(ctx, "g")
	require.NoError(t, err)
	assert.Equal(t, "v2", g.Description)
	assert.Equal(t, h2, hash)

	assert.Equal(t, http.StatusConflict,
		groupRequest(t, c, logical.DeleteOperation, "group/g", map[string]any{"type": "virtual", "expected_hash": h1}).StatusCode)
	resp = groupRequest(t, c, logical.CreateOperation, "group/fresh", map[string]any{"expected_hash": "x", "type": "virtual"})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "expected_hash means nothing on a create")

	// One retry without expected_hash; a second loss is a 409.
	c.identityStore.beforeGroupUpdate = func() {
		// Land one concurrent write, once.
		c.identityStore.beforeGroupUpdate = nil
		_, err := c.identityStore.UpdateGroup(ctx, virtualGroup("g", "other"), "")
		require.NoError(t, err)
	}
	resp = groupRequest(t, c, logical.UpdateOperation, "group/g", map[string]any{"type": "virtual", "description": "v3"})
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
	resp = groupRequest(t, c, logical.UpdateOperation, "group/g", map[string]any{"type": "virtual", "description": "v4"})
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
	body["type"] = ""
	resp = groupRequest(t, c, logical.CreateOperation, "group/g", body)
	assert.Contains(t, resp.Err.Error(), "type is required", "an empty type is no type on create")

	for _, typ := range []string{"static", "directory"} {
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

	// Every write names the type, so a policy condition on it can tell who may
	// write which type of group.
	for _, typ := range []any{nil, ""} {
		body := map[string]any{"description": "no type"}
		if typ != nil {
			body["type"] = typ
		}
		resp = groupRequest(t, c, logical.UpdateOperation, "group/g", body)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "update with type %v", typ)
		assert.Contains(t, resp.Err.Error(), "type is required on update")
		del := map[string]any{}
		if typ != nil {
			del["type"] = typ
		}
		resp = groupRequest(t, c, logical.DeleteOperation, "group/g", del)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "delete with type %v", typ)
		assert.Contains(t, resp.Err.Error(), "type is required on delete")
	}
	resp = groupRequest(t, c, logical.UpdateOperation, "group/g", map[string]any{"type": "virtual", "description": "same"})
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	assert.Equal(t, "virtual", resp.Data["type"])

	// A type other than the stored one is refused on every operation that names it.
	resp = groupRequest(t, c, logical.UpdateOperation, "group/g", map[string]any{"type": "static", "description": "x"})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, resp.Err.Error(), `type mismatch: group "g" is virtual`)
	resp = groupRequest(t, c, logical.DeleteOperation, "group/g", map[string]any{"type": "static"})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, resp.Err.Error(), `type mismatch: group "g" is virtual`)
	resp = groupRequest(t, c, logical.ReadOperation, "group/g", map[string]any{"type": "static"})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, resp.Err.Error(), `type mismatch: group "g" is virtual`)
	resp = groupRequest(t, c, logical.ReadOperation, "group/g", map[string]any{"type": "selector"})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, resp.Err.Error(), "unknown group type")
	resp = groupRequest(t, c, logical.ReadOperation, "group/g", virtualType())
	assert.Equal(t, http.StatusOK, resp.StatusCode, "a read naming the stored type")
	resp = groupRequest(t, c, logical.ReadOperation, "group/g", nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "type is optional on read")
	_, _, err := c.identityStore.GetGroup(rootCtx(), "g")
	require.NoError(t, err, "nothing was deleted")

	resp = groupRequest(t, c, logical.UpdateOperation, "group/g", map[string]any{"type": "virtual", "members": []any{"bot"}})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// The store refuses a type change too (static groups are refused before
	// the type is compared, as long as they are not accepted), and a delete
	// naming another type.
	g := virtualGroup("g")
	g.Type = logical.GroupTypeStatic
	_, err = c.identityStore.UpdateGroup(rootCtx(), g, "")
	assert.Error(t, err)
	var mismatch *GroupTypeMismatchError
	err = c.identityStore.DeleteGroup(rootCtx(), "g", logical.GroupTypeStatic, "")
	assert.ErrorAs(t, err, &mismatch)
	assert.Equal(t, logical.GroupTypeVirtual, mismatch.Stored)
}

// virtualType is the request data naming the virtual type, for the operations
// that carry nothing else.
func virtualType() map[string]any {
	return map[string]any{"type": "virtual"}
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

	create := func(rules ...logical.GroupRule) ([]string, error) {
		return c.identityStore.CreateGroup(ctx, &logical.Group{
			Name: "g", Type: logical.GroupTypeVirtual, Rules: rules,
		})
	}

	_, err := create()
	assert.Equal(t, http.StatusBadRequest, logical.GetErrorCode(err), "a virtual group needs a rule")
	assert.Contains(t, err.Error(), "a virtual group needs at least one rule")

	_, err = create(logical.GroupRule{"mount": {"auth/jwt/"}}, logical.GroupRule{"sub": {"x"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `rules[1]: every rule must include a "mount" selector`)

	for _, s := range []logical.GroupRule{
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

	tooMany := make([]logical.GroupRule, logical.MaxGroupRules+1)
	for i := range tooMany {
		tooMany[i] = logical.GroupRule{"mount": {"auth/jwt/"}, "sub": {fmt.Sprint(i)}}
	}
	_, err = create(tooMany...)
	assert.Equal(t, http.StatusBadRequest, logical.GetErrorCode(err))
	_, err = create(tooMany[:logical.MaxGroupRules]...)
	assert.NoError(t, err)

	// Any mount value holding "**" is accepted with a warning; one "*" is not
	// warned about.
	for i, v := range []string{"**", "**/", "a**", "**/**", "auth/**", "auth/k8s-**/"} {
		warnings, err := c.identityStore.CreateGroup(ctx, &logical.Group{
			Name: fmt.Sprintf("any-%d", i), Type: logical.GroupTypeVirtual,
			Rules: []logical.GroupRule{{"mount": {v}, "sub": {"x"}}},
		})
		require.NoError(t, err, "%q is accepted", v)
		assert.Contains(t, warnings, fmt.Sprintf(
			`rules[0]: mount %q uses "**", which matches across "/": it trusts every auth mount it reaches, including ones enabled later`, v))
	}
	warnings, err := c.identityStore.CreateGroup(ctx, &logical.Group{
		Name: "one-star", Type: logical.GroupTypeVirtual,
		Rules: []logical.GroupRule{{"mount": {"auth/*/", `auth/\*\*/`}, "sub": {"x"}}},
	})
	require.NoError(t, err)
	for _, w := range warnings {
		assert.NotContains(t, w, `uses "**"`, "a single * and an escaped ** are not warned about")
	}

	// Through the API: a rule is an object, and each value a list of strings
	// or one string.
	for _, sel := range []any{"x", map[string]any{"mount": []any{1}}, map[string]any{"mount": 1}} {
		resp := groupRequest(t, c, logical.CreateOperation, "group/api", map[string]any{
			"type": "virtual", "rules": []any{sel},
		})
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "%v", sel)
	}
}

// TestGroups_ScalarSelectorValue: a selector value written as one string is a
// one-element list, on create and on update.
func TestGroups_ScalarSelectorValue(t *testing.T) {
	c := createTestCore(t)

	resp := groupRequest(t, c, logical.CreateOperation, "group/g", map[string]any{
		"type":  "virtual",
		"rules": []any{map[string]any{"mount": "auth/jwt/", "sub": []any{"a", "b"}}},
	})
	require.Equal(t, http.StatusCreated, resp.StatusCode, "%v", resp.Err)
	assert.Equal(t, []map[string][]string{{"mount": {"auth/jwt/"}, "sub": {"a", "b"}}}, resp.Data["rules"])

	resp = groupRequest(t, c, logical.UpdateOperation, "group/g", map[string]any{
		"type":  "virtual",
		"rules": []any{map[string]any{"mount": "auth/k8s/", "workload": "ci"}},
	})
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	assert.Equal(t, []map[string][]string{{"mount": {"auth/k8s/"}, "workload": {"ci"}}}, resp.Data["rules"])
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
		require.NoError(t, c.identityStore.DeleteGroup(ctx, "g", "", ""))
		return w
	}

	// A built-in or mapped name of a listed mount, and mount/kind: no warning.
	assert.Empty(t, warn(&logical.Group{Rules: []logical.GroupRule{
		{"mount": {"auth/github-oidc/"}, "repo": {"acme/*"}, "sub": {"x"}, "kind": {"agent"}},
	}}))

	// A name only an unlisted mount produces warns: facts are checked against
	// the rule's own mounts.
	assert.Equal(t, []string{
		`rules[0]: no auth mount the rule lists produces fact "workload"; its selector cannot match until one maps it`,
	}, warn(&logical.Group{Rules: []logical.GroupRule{
		{"mount": {"auth/github-oidc/"}, "workload": {"x"}},
	}}))

	// Listing both mounts: one of them produces it.
	assert.Empty(t, warn(&logical.Group{Rules: []logical.GroupRule{
		{"mount": {"auth/github-oidc/", "auth/k8s/"}, "workload": {"x"}},
	}}))

	// A glob that lists both reaches them too.
	assert.Empty(t, warn(&logical.Group{Rules: []logical.GroupRule{
		{"mount": {"auth/*/"}, "workload": {"x"}, "repo": {"y"}},
	}}))

	// A literal mount naming no mount warns; facts are then not checked.
	assert.Equal(t, []string{
		`rules[0]: mount "auth/gone/" names no auth mount in this namespace; the rule cannot match through it until one is enabled there`,
	}, warn(&logical.Group{Rules: []logical.GroupRule{{"mount": {"auth/gone/"}, "email": {"x"}}}}))
	assert.Equal(t, []string{
		`rules[0]: no auth mount in this namespace matches the rule's "mount" selector`,
	}, warn(&logical.Group{Rules: []logical.GroupRule{{"mount": {"auth/zz-*/"}, "email": {"x"}}}}))

	// An unknown kind never matches.
	assert.Contains(t, warn(&logical.Group{Rules: []logical.GroupRule{
		{"mount": {"auth/k8s/"}, "kind": {"robot"}},
	}}), `rules[0]: the "kind" selector's value "robot" is neither "agent" nor "human" and never matches`)

	// Warnings are indexed by rule.
	w := warn(&logical.Group{Rules: []logical.GroupRule{
		{"mount": {"auth/k8s/"}, "workload": {"x"}},
		{"mount": {"auth/k8s/"}, "repo": {"x"}},
	}})
	assert.Equal(t, []string{
		`rules[1]: no auth mount the rule lists produces fact "repo"; its selector cannot match until one maps it`,
	}, w)
}

// TestGroups_ValidUntil: valid_until is an RFC 3339 instant, stored in UTC; a
// past one is stored with a warning; an empty one clears it; anything else is
// refused; max_age is no field any more.
func TestGroups_ValidUntil(t *testing.T) {
	c := createTestCore(t)
	ctx := rootCtx()
	pastWarning := "valid_until is in the past; the group grants nothing"

	future := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	body := deployersBody()
	body["valid_until"] = future.Format(time.RFC3339)
	resp := groupRequest(t, c, logical.CreateOperation, "group/g", body)
	require.Equal(t, http.StatusCreated, resp.StatusCode, "%v", resp.Err)
	assert.NotContains(t, respWarnings(resp), pastWarning)
	g, _, err := c.identityStore.GetGroup(ctx, "g")
	require.NoError(t, err)
	assert.True(t, future.Equal(g.ValidUntil))
	assert.Equal(t, time.UTC, g.ValidUntil.Location())

	// A past value is stored, with a warning.
	past := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	resp = groupRequest(t, c, logical.UpdateOperation, "group/g", map[string]any{"type": "virtual", "valid_until": past.Format(time.RFC3339)})
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	assert.Contains(t, respWarnings(resp), pastWarning)
	assert.Equal(t, past.Format(time.RFC3339), resp.Data["valid_until"])

	// Sub-second precision survives a round trip.
	resp = groupRequest(t, c, logical.UpdateOperation, "group/g", map[string]any{"type": "virtual", "valid_until": "2099-01-02T03:04:05.123456789Z"})
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	assert.Equal(t, "2099-01-02T03:04:05.123456789Z", resp.Data["valid_until"])

	// Clearing it.
	resp = groupRequest(t, c, logical.UpdateOperation, "group/g", map[string]any{"type": "virtual", "valid_until": ""})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	g, _, err = c.identityStore.GetGroup(ctx, "g")
	require.NoError(t, err)
	assert.True(t, g.ValidUntil.IsZero())

	for _, bad := range []string{"tomorrow", "2026-12-31", "10m", "1767225599"} {
		resp = groupRequest(t, c, logical.UpdateOperation, "group/g", map[string]any{"type": "virtual", "valid_until": bad})
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, bad)
		assert.Contains(t, resp.Err.Error(), "valid_until must be an RFC 3339 timestamp", bad)
	}

	// max_age is ignored as an unrecognised field, and changes nothing.
	_, hash, err := c.identityStore.GetGroup(ctx, "g")
	require.NoError(t, err)
	resp = groupRequest(t, c, logical.UpdateOperation, "group/g", map[string]any{"type": "virtual", "max_age": "10m"})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Warnings, "Endpoint ignored these unrecognized parameters: [max_age]")
	_, hash2, err := c.identityStore.GetGroup(ctx, "g")
	require.NoError(t, err)
	assert.Equal(t, hash, hash2)

	// The value survives a reload.
	at := time.Date(2099, 6, 1, 12, 0, 0, 0, time.UTC)
	_, err = c.identityStore.UpdateGroup(ctx, &logical.Group{Name: "g", Type: logical.GroupTypeVirtual,
		Rules: []logical.GroupRule{{"mount": {"auth/jwt/"}}}, ValidUntil: at}, "")
	require.NoError(t, err)
	c.teardownIdentityStore()
	require.NoError(t, c.setupIdentityStore(ctx, false))
	g, _, err = c.identityStore.GetGroup(ctx, "g")
	require.NoError(t, err)
	assert.True(t, at.Equal(g.ValidUntil))
	assert.True(t, at.Equal(c.identityStore.namespaceIndex(namespace.RootNamespaceID).groupsByName["g"].ValidUntil),
		"the published group entry carries it")
}

// TestGroups_ValidUntilThroughMembership: a stored group grants through its
// valid_until and not a nanosecond after, to a cached admission.
func TestGroups_ValidUntilThroughMembership(t *testing.T) {
	c := createTestCore(t)
	ctx := rootCtx()
	end := time.Now().Add(time.Hour).UTC().Round(0)
	_, err := c.identityStore.CreateGroup(ctx, &logical.Group{Name: "g", Type: logical.GroupTypeVirtual,
		Roles: []string{"deploy"}, Rules: []logical.GroupRule{{"mount": {"auth/jwt/"}, "sub": {"a"}}}, ValidUntil: end})
	require.NoError(t, err)
	adm := groupAdmission(t, "auth/jwt/", "", map[string]any{"sub": "a"}, time.Time{})
	gs := c.identityStore.namespaceIndex(namespace.RootNamespaceID)

	m := membership(adm, gs, end)
	assert.Contains(t, m.Roles, "deploy", "granted at valid_until")
	m = membership(adm, gs, end.Add(time.Nanosecond))
	assert.NotContains(t, m.Roles, "deploy", "refused a nanosecond after")
	assert.Empty(t, m.Groups)
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

	// The namespace caps, lowered for the test.
	other := namespace.ContextWithNamespace(context.Background(),
		&namespace.Namespace{ID: "caps-ns", UUID: "caps-ns-uuid", Path: "caps/"})
	c.identityStore.maxVirtualGroups.Store(3)
	c.identityStore.maxSelectors.Store(7)

	// virtualGroup's one rule has two selectors: mount and sub.
	for _, n := range []string{"a", "b", "c"} {
		_, err := c.identityStore.CreateGroup(other, virtualGroup(n))
		require.NoError(t, err)
	}
	assert.Equal(t, 6, c.identityStore.namespaceIndex("caps-ns").selectors)
	_, err = c.identityStore.CreateGroup(other, virtualGroup("d"))
	assert.ErrorIs(t, err, ErrTooManyVirtualGroups)
	assert.EqualError(t, err, "too many virtual groups in the namespace: the namespace has 3/3 virtual groups")
	resp := roleRequest(t, c, other, logical.CreateOperation, "identity/group/d", deployersBody())
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, resp.Err.Error(), "the namespace has 3/3 virtual groups")

	// An update counts the selectors it replaces and adds: 6 - 2 + 4 = 8 is
	// over, 6 - 2 + 3 = 7 is exactly the cap.
	over := virtualGroup("a")
	over.Rules = append(over.Rules, logical.GroupRule{"mount": {"auth/jwt/"}, "sub": {"y"}})
	_, err = c.identityStore.UpdateGroup(other, over, "")
	assert.ErrorIs(t, err, ErrTooManySelectors)
	resp = roleRequest(t, c, other, logical.UpdateOperation, "identity/group/a", map[string]any{
		"type": "virtual",
		"rules": []any{
			map[string]any{"mount": "auth/jwt/", "sub": "x"},
			map[string]any{"mount": "auth/jwt/", "sub": "y"},
		},
	})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, resp.Err.Error(),
		`too many selectors in the namespace: this write would make 8/7 virtual selectors (currently 6; every key of every rule counts, "mount" included)`)
	at := virtualGroup("a")
	at.Rules = append(at.Rules, logical.GroupRule{"mount": {"auth/jwt/"}})
	_, err = c.identityStore.UpdateGroup(other, at, "")
	require.NoError(t, err, "exactly at the cap")
	assert.Equal(t, 7, c.identityStore.namespaceIndex("caps-ns").selectors)

	// A create counts its selectors; a delete gives them back.
	require.NoError(t, c.identityStore.DeleteGroup(other, "c", "", ""))
	g = virtualGroup("e")
	g.Rules[0]["iss"] = []string{"z"}
	_, err = c.identityStore.CreateGroup(other, g)
	assert.ErrorIs(t, err, ErrTooManySelectors, "5 + 3 is over")
	assert.Contains(t, err.Error(), "this write would make 8/7 virtual selectors (currently 5;")
	_, err = c.identityStore.CreateGroup(other, virtualGroup("e"))
	require.NoError(t, err, "5 + 2 is exactly the cap")
}

// readUsage reads sys/identity/usage in the root namespace and returns its
// groups section.
func readUsage(t *testing.T, c *Core) GroupsUsage {
	t.Helper()
	resp := roleRequest(t, c, rootCtx(), logical.ReadOperation, "identity/usage", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	assert.Len(t, resp.Data, 2, "groups and identities")
	return resp.Data["groups"].(GroupsUsage)
}

// TestIdentityUsage: sys/identity/usage counts the namespace's groups, and
// the virtual groups and their selectors against the caps, after every kind of
// write; a listing carries no usage; every group reports what it adds.
func TestIdentityUsage(t *testing.T) {
	c := createTestCore(t)
	want := func(groups, selectors int) GroupsUsage {
		return GroupsUsage{Total: groups, Virtual: VirtualGroupsUsage{
			Count:        groups,
			Max:          logical.MaxVirtualGroupsPerNamespace,
			Selectors:    selectors,
			MaxSelectors: logical.MaxSelectorsPerNamespace,
		}}
	}

	assert.Equal(t, want(0, 0), readUsage(t, c), "an empty namespace")

	resp := groupRequest(t, c, logical.CreateOperation, "group/deployers", deployersBody()) // 1 rule, 2 selectors
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	resp = groupRequest(t, c, logical.CreateOperation, "group/readers", map[string]any{
		"type":  "virtual",
		"roles": []any{"read-secrets"},
		"rules": []any{
			map[string]any{"mount": "auth/jwt/", "sub": "r", "iss": "i"},
			map[string]any{"mount": "auth/k8s/"},
		},
	})
	require.Equal(t, http.StatusCreated, resp.StatusCode, "%v", resp.Err)
	assert.Equal(t, 2, resp.Data["rule_count"])
	assert.Equal(t, 4, resp.Data["selector_count"])
	assert.Equal(t, want(2, 6), readUsage(t, c), "after creates")

	// A listing carries the groups only, filtered or not.
	for _, data := range []map[string]any{nil, {"role": "deploy"}} {
		resp = groupRequest(t, c, logical.ListOperation, "group", data)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		assert.NotContains(t, resp.Data, "usage")
	}

	resp = groupRequest(t, c, logical.UpdateOperation, "group/readers", map[string]any{
		"type":  "virtual",
		"rules": []any{map[string]any{"mount": "auth/jwt/"}},
	})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 1, resp.Data["rule_count"])
	assert.Equal(t, 1, resp.Data["selector_count"])
	assert.Equal(t, want(2, 3), readUsage(t, c), "after an update")

	resp = groupRequest(t, c, logical.ReadOperation, "group/deployers", nil)
	assert.Equal(t, 1, resp.Data["rule_count"])
	assert.Equal(t, 2, resp.Data["selector_count"])

	require.Equal(t, http.StatusOK, groupRequest(t, c, logical.DeleteOperation, "group/deployers", virtualType()).StatusCode)
	assert.Equal(t, want(1, 1), readUsage(t, c), "after a delete")

	// Every listed group reports its own counts.
	resp = groupRequest(t, c, logical.ListOperation, "group", nil)
	items := resp.Data["groups"].([]map[string]any)
	require.Len(t, items, 1)
	assert.Equal(t, 1, items[0]["rule_count"])
	assert.Equal(t, 1, items[0]["selector_count"])

	// The usage reports the caps in force, and only its own namespace.
	c.identityStore.maxVirtualGroups.Store(5)
	assert.Equal(t, 5, readUsage(t, c).Virtual.Max)
	other := namespace.ContextWithNamespace(context.Background(),
		&namespace.Namespace{ID: "usage-ns", UUID: "usage-ns-uuid", Path: "usage/"})
	_, err := c.identityStore.CreateGroup(other, virtualGroup("elsewhere"))
	require.NoError(t, err)
	assert.Equal(t, 1, readUsage(t, c).Total)
	u, err := c.identityStore.Usage(other)
	require.NoError(t, err)
	assert.Equal(t, 1, u.Groups.Virtual.Count)
	assert.Equal(t, 2, u.Groups.Virtual.Selectors)
}

// TestIdentityUsage_HTTP: GET sys/identity/usage through the request path
// returns data keyed by kind.
func TestIdentityUsage_HTTP(t *testing.T) {
	c := createTestCore(t)
	root, err := c.tokenStore.GenerateRootToken()
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated,
		roleHTTP(t, c, root, http.MethodPost, "/v1/sys/identity/group/deployers", deployersBody()).StatusCode)

	resp := roleHTTP(t, c, root, http.MethodGet, "/v1/sys/identity/usage", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	raw, err := json.Marshal(resp.Data)
	require.NoError(t, err)
	assert.JSONEq(t, `{
		"groups": {
			"total": 1,
			"virtual": {"count": 1, "max": 8000, "selectors": 2, "max_selectors": 16000}
		},
		"identities": {"entities": 0, "max_entities": 50000, "aliases": 0}
	}`, string(raw))
}

// TestGroups_OldSelectorsField: "selectors" is no field of the group path. The
// framework ignores it with a response warning rather than refusing it, so a
// create carrying rules only under it has no rules and is refused, and an
// update carrying only it changes nothing and says so.
func TestGroups_OldSelectorsField(t *testing.T) {
	c := createTestCore(t)
	old := []any{map[string]any{"mount": []any{"auth/jwt/"}, "sub": []any{"x"}}}

	resp := groupRequest(t, c, logical.CreateOperation, "group/g", map[string]any{"type": "virtual", "selectors": old})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, resp.Err.Error(), "a virtual group needs at least one rule")

	require.Equal(t, http.StatusCreated, groupRequest(t, c, logical.CreateOperation, "group/g", deployersBody()).StatusCode)
	before, hash, err := c.identityStore.GetGroup(rootCtx(), "g")
	require.NoError(t, err)
	resp = groupRequest(t, c, logical.UpdateOperation, "group/g", map[string]any{"type": "virtual", "selectors": old})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Warnings, "Endpoint ignored these unrecognized parameters: [selectors]")
	after, hash2, err := c.identityStore.GetGroup(rootCtx(), "g")
	require.NoError(t, err)
	assert.Equal(t, before.Rules, after.Rules, "the rules are untouched")
	assert.Equal(t, hash, hash2)
}

// TestGroups_RoleFilterAndHTTP drives the paths through the request path:
// LIST ?role= and ?type=, and DELETE ?type= and ?expected_hash=, reach the
// handlers, and the token is checked.
func TestGroups_RoleFilterAndHTTP(t *testing.T) {
	c := createTestCore(t)
	root, err := c.tokenStore.GenerateRootToken()
	require.NoError(t, err)

	resp := roleHTTP(t, c, root, http.MethodPost, "/v1/sys/identity/group/deployers", deployersBody())
	require.Equal(t, http.StatusCreated, resp.StatusCode, "%v", resp.Err)
	hash := resp.Data["hash"].(string)
	resp = roleHTTP(t, c, root, http.MethodPost, "/v1/sys/identity/group/readers", map[string]any{
		"type":  "virtual",
		"roles": []string{"read-secrets"},
		"rules": []any{map[string]any{"mount": []string{"auth/jwt/"}, "sub": []string{"r"}}},
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
	resp = roleHTTP(t, c, root, http.MethodGet, "/v1/sys/identity/group?warden-list=true&type=virtual", nil)
	assert.Equal(t, []string{"deployers", "readers"}, resp.Data["keys"])
	resp = roleHTTP(t, c, root, http.MethodGet, "/v1/sys/identity/group?warden-list=true&type=static", nil)
	assert.Equal(t, []string{}, resp.Data["keys"], "no static group yet")
	resp = roleHTTP(t, c, root, http.MethodGet, "/v1/sys/identity/group?warden-list=true&type=selector", nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	resp = roleHTTP(t, c, root, http.MethodDelete, "/v1/sys/identity/group/deployers?expected_hash="+hash, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "a delete names the type")
	resp = roleHTTP(t, c, root, http.MethodDelete, "/v1/sys/identity/group/deployers?type=static&expected_hash="+hash, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "a delete naming another type")
	resp = roleHTTP(t, c, root, http.MethodDelete, "/v1/sys/identity/group/deployers?type=virtual&expected_hash=stale", nil)
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	resp = roleHTTP(t, c, root, http.MethodDelete, "/v1/sys/identity/group/deployers?type=virtual&expected_hash="+hash, nil)
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

// TestGroups_TypeConditionSeparatesWriters: since every group write names its
// type, a policy condition on request.data.type lets one team write virtual
// groups and nothing else. The condition is path-level, so it gates reads
// too, and conditions merge with "unconditional wins": a second, unconditional
// stanza on the same path, even read-only, makes every capability on it
// unconditional.
func TestGroups_TypeConditionSeparatesWriters(t *testing.T) {
	c := createTestCore(t)
	ctx := rootCtx()
	const path = "sys/identity/group/g"
	recipe := testParsePolicy(t, `path "sys/identity/group/*" {
		capabilities = ["create", "read", "update", "delete", "list", "sudo"]
		condition    = "has(request.data.type) && request.data.type == 'virtual'"
	}`)
	allowed := func(cbp *CBP, op logical.Operation, data map[string]any) bool {
		t.Helper()
		req := &logical.Request{Operation: op, Path: path, Data: data}
		return c.performPolicyChecks(ctx, cbp, nil, req,
			&PolicyCheckOpts{RootPrivsRequired: c.router.RootPath(ctx, path)}).Allowed
	}

	platform, err := NewCBP(ctx, []*Policy{recipe})
	require.NoError(t, err)
	for _, op := range []logical.Operation{logical.CreateOperation, logical.UpdateOperation, logical.DeleteOperation} {
		assert.True(t, allowed(platform, op, map[string]any{"type": "virtual"}), "%s of a virtual group", op)
		for _, typ := range []string{"static", "directory"} {
			assert.False(t, allowed(platform, op, map[string]any{"type": typ}), "%s of a %s group", op, typ)
		}
		assert.False(t, allowed(platform, op, nil), "%s naming no type", op)
	}
	assert.True(t, allowed(platform, logical.ReadOperation, map[string]any{"type": "virtual"}), "a read naming the type")
	assert.False(t, allowed(platform, logical.ReadOperation, nil), "the condition gates reads too")

	readOnly := testParsePolicy(t, `path "sys/identity/group/*" { capabilities = ["read", "sudo"] }`)
	merged, err := NewCBP(ctx, []*Policy{recipe, readOnly})
	require.NoError(t, err)
	assert.True(t, allowed(merged, logical.UpdateOperation, map[string]any{"type": "static"}),
		"an unconditional stanza on the same path makes the recipe's writes unconditional")
}

// TestIdentityUsage_NormalACL: sys/identity/usage is not a root path. A token
// whose policy grants read on it, without sudo, reads it; the same token is
// refused the group paths, which need sudo however broad the policy.
func TestIdentityUsage_NormalACL(t *testing.T) {
	c := createTestCore(t)
	ctx := rootCtx()

	assert.False(t, c.router.RootPath(ctx, "sys/identity/usage"), "usage needs no sudo")
	for _, p := range []string{"sys/identity/group", "sys/identity/group/", "sys/identity/group/x"} {
		assert.True(t, c.router.RootPath(ctx, p), "%s still needs sudo", p)
	}

	check := func(cbp *CBP, op logical.Operation, path string) bool {
		t.Helper()
		req := &logical.Request{Operation: op, Path: path}
		return c.performPolicyChecks(ctx, cbp, nil, req,
			&PolicyCheckOpts{RootPrivsRequired: c.router.RootPath(ctx, path)}).Allowed
	}

	reader, err := NewCBP(ctx, []*Policy{testParsePolicy(t,
		`path "sys/identity/usage" { capabilities = ["read"] }`)})
	require.NoError(t, err)
	assert.True(t, check(reader, logical.ReadOperation, "sys/identity/usage"), "read on the path is enough")
	assert.False(t, check(reader, logical.ListOperation, "sys/identity/group"))
	assert.False(t, check(reader, logical.ReadOperation, "sys/identity/group/g"))

	broad, err := NewCBP(ctx, []*Policy{testParsePolicy(t,
		`path "sys/identity/*" { capabilities = ["create", "read", "update", "delete", "list"] }
		 path "sys/identity/group" { capabilities = ["list"] }`)})
	require.NoError(t, err)
	assert.True(t, check(broad, logical.ReadOperation, "sys/identity/usage"))
	assert.False(t, check(broad, logical.ReadOperation, "sys/identity/group/g"), "group paths need sudo")
	assert.False(t, check(broad, logical.ListOperation, "sys/identity/group"), "the group list needs sudo")

	none, err := NewCBP(ctx, []*Policy{testParsePolicy(t,
		`path "sys/roles/*" { capabilities = ["read"] }`)})
	require.NoError(t, err)
	assert.False(t, check(none, logical.ReadOperation, "sys/identity/usage"), "it is still an ACL path")
}

// TestIdentityUsage_NonSudoToken drives the request path with a token whose
// one policy grants read on sys/identity/usage: the usage answers, the group
// paths refuse it.
func TestIdentityUsage_NonSudoToken(t *testing.T) {
	c := createTestCore(t)
	ctx := rootCtx()

	p := testParsePolicy(t, `path "sys/identity/usage" { capabilities = ["read"] }
		path "sys/identity/group" { capabilities = ["list"] }
		path "sys/identity/group/*" { capabilities = ["read"] }`)
	p.Name, p.Type = "usage-reader", PolicyTypeCBP
	require.NoError(t, c.policyStore.SetPolicy(ctx, p, nil))
	te, err := c.tokenStore.GenerateToken(ctx, TypeServiceToken, &AuthData{
		PrincipalID: "operator",
		ExpireAt:    time.Now().Add(time.Hour),
		Policies:    []string{"usage-reader"},
	})
	require.NoError(t, err)
	token := te.Data["token"]
	require.NotEmpty(t, token)

	resp := roleHTTP(t, c, token, http.MethodGet, "/v1/sys/identity/usage", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	assert.Equal(t, logical.MaxVirtualGroupsPerNamespace, resp.Data["groups"].(GroupsUsage).Virtual.Max)

	for _, target := range []string{"/v1/sys/identity/group?warden-list=true", "/v1/sys/identity/group/g"} {
		httpReq := httptest.NewRequest(http.MethodGet, target, nil)
		httpReq.Header.Set("X-Warden-Token", token)
		op := logical.ReadOperation
		if httpReq.URL.Query().Get("warden-list") == "true" {
			op = logical.ListOperation
		}
		resp, err := c.HandleRequest(rootCtx(), &logical.Request{
			Path: strings.TrimPrefix(httpReq.URL.Path, "/v1/"), Operation: op, HTTPRequest: httpReq,
		})
		refused := err != nil || (resp != nil && resp.StatusCode == http.StatusForbidden)
		assert.True(t, refused, "%s needs sudo the token does not have", target)
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
	raw := `{"version":1,"group":{"id":"zz-dup","name":"deployers","type":"virtual","roles":["other"],"rules":[{"mount":["auth/jwt/"],"sub":["x"]}]}}`
	require.NoError(t, view.Put(ctx, &sdklogical.StorageEntry{Key: groupStorageKey(namespace.RootNamespaceUUID, dup.ID), Value: []byte(raw)}))

	c.teardownIdentityStore()
	_, _, err = c.identityStore.GetGroup(ctx, "deployers")
	assert.ErrorIs(t, err, ErrGroupNotFound, "an unloaded store serves nothing")
	assert.Same(t, emptyNSIndex, c.identityStore.namespaceIndex(namespace.RootNamespaceID))
	_, err = c.identityStore.CreateGroup(ctx, virtualGroup("x"))
	assert.ErrorIs(t, err, ErrIdentityStoreNotLoaded)

	require.NoError(t, c.setupIdentityStore(ctx, false))
	got, hash, err := c.identityStore.GetGroup(ctx, "deployers")
	require.NoError(t, err)
	assert.Equal(t, want.ID, got.ID, "the first record by ID keeps the name")
	assert.Equal(t, wantHash, hash)
	gs := c.identityStore.namespaceIndex(namespace.RootNamespaceID)
	require.Len(t, gs.virtualGroups, 1)
	require.NotNil(t, gs.virtualGroups[0].rules)
	assert.NotEmpty(t, gs.virtualGroups[0].rules.compiled, "loaded groups are compiled")

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

	require.NoError(t, active.StepDown())
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
	rootGS := c.identityStore.namespaceIndex(namespace.RootNamespaceID)

	require.NoError(t, c.namespaceStore.clearNamespaceResources(childCtx, child))

	groups, _, err := c.identityStore.ListGroups(childCtx, "")
	require.NoError(t, err)
	assert.Empty(t, groups)
	assert.Same(t, emptyNSIndex, c.identityStore.namespaceIndex(child.ID))
	keys, err := c.identityStore.storage.List(context.Background(), groupListPrefix(child.UUID))
	require.NoError(t, err)
	assert.Empty(t, keys, "the namespace's records are deleted from storage")
	assert.Same(t, rootGS, c.identityStore.namespaceIndex(namespace.RootNamespaceID), "other namespaces are untouched")
}
