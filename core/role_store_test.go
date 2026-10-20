package core

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// roleRequest drives the system backend's role paths the way the router does,
// so the path pattern and the field schema apply.
func roleRequest(t *testing.T, c *Core, ctx context.Context, op logical.Operation, path string, data map[string]any) *logical.Response {
	t.Helper()
	resp, err := c.systemBackend.HandleRequest(ctx, &logical.Request{
		Operation: op,
		Path:      path,
		Data:      data,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	return resp
}

func rootCtx() context.Context {
	return namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
}

func respWarnings(resp *logical.Response) []string {
	w, _ := resp.Data["warnings"].([]string)
	return w
}

func TestRoles_CRUD(t *testing.T) {
	c := createTestCore(t)
	ctx := rootCtx()

	resp := roleRequest(t, c, ctx, logical.CreateOperation, "roles/deploy", map[string]any{
		"description":    "Deploys from acme CI",
		"policies":       []any{"Deploy", "audit", "deploy"},
		"cred_spec_name": "deploy-role",
		"skill":          "aws",
		"provider_path":  "aws",
		"metadata":       map[string]any{"team": "platform"},
	})
	require.Equal(t, http.StatusCreated, resp.StatusCode, "%v", resp.Err)
	assert.Equal(t, "deploy", resp.Data["name"])
	assert.Equal(t, []string{"audit", "deploy"}, resp.Data["policies"], "policies are lower-cased, sorted, deduplicated")
	assert.Equal(t, "aws/", resp.Data["provider_path"], "provider_path gains its trailing slash")
	assert.Equal(t, map[string]string{"team": "platform"}, resp.Data["metadata"])
	createdHash, _ := resp.Data["hash"].(string)
	require.NotEmpty(t, createdHash)

	resp = roleRequest(t, c, ctx, logical.CreateOperation, "roles/deploy", map[string]any{})
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "a second create of the same name is refused")

	resp = roleRequest(t, c, ctx, logical.ReadOperation, "roles/deploy", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "Deploys from acme CI", resp.Data["description"])
	assert.Equal(t, "deploy-role", resp.Data["cred_spec_name"])
	assert.Equal(t, createdHash, resp.Data["hash"])
	created := resp.Data["created_at"].(time.Time)

	// An update replaces the fields it names, including with an empty value, and
	// keeps the others.
	resp = roleRequest(t, c, ctx, logical.UpdateOperation, "roles/deploy", map[string]any{
		"policies":       []any{"deploy"},
		"cred_spec_name": "",
	})
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	assert.Equal(t, []string{"deploy"}, resp.Data["policies"])
	assert.Equal(t, "", resp.Data["cred_spec_name"])
	assert.Equal(t, "Deploys from acme CI", resp.Data["description"])
	assert.Equal(t, "aws/", resp.Data["provider_path"])
	assert.Equal(t, created, resp.Data["created_at"], "an update keeps the creation time")
	assert.NotEqual(t, createdHash, resp.Data["hash"])

	resp = roleRequest(t, c, ctx, logical.CreateOperation, "roles/read-secrets", map[string]any{
		"provider_path": "vault/",
	})
	require.Equal(t, http.StatusCreated, resp.StatusCode, "%v", resp.Err)

	resp = roleRequest(t, c, ctx, logical.ListOperation, "roles", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, []string{"deploy", "read-secrets"}, resp.Data["keys"])
	require.Len(t, resp.Data["roles"], 2)

	resp = roleRequest(t, c, ctx, logical.ListOperation, "roles/", map[string]any{"provider_path": "vault"})
	assert.Equal(t, []string{"read-secrets"}, resp.Data["keys"], "provider_path filters the list")

	resp = roleRequest(t, c, ctx, logical.DeleteOperation, "roles/deploy", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp = roleRequest(t, c, ctx, logical.ReadOperation, "roles/deploy", nil)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp = roleRequest(t, c, ctx, logical.DeleteOperation, "roles/deploy", nil)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "deleting a missing role is a 404")
	resp = roleRequest(t, c, ctx, logical.UpdateOperation, "roles/deploy", map[string]any{"description": "x"})
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestRoles_NamespaceIsolation(t *testing.T) {
	c := createTestCore(t)
	child := &namespace.Namespace{ID: "child-ns", UUID: "child-ns-uuid", Path: "child/"}
	childCtx := namespace.ContextWithNamespace(context.Background(), child)

	_, err := c.roleStore.Create(rootCtx(), &logical.Role{Name: "deploy"})
	require.NoError(t, err)

	_, _, err = c.roleStore.Get(childCtx, "deploy")
	assert.ErrorIs(t, err, ErrRoleNotFound, "a role is scoped to its namespace")
	_, err = c.roleStore.Create(childCtx, &logical.Role{Name: "deploy", Description: "child"})
	require.NoError(t, err, "the same name is free in another namespace")

	r, _, err := c.roleStore.Get(childCtx, "deploy")
	require.NoError(t, err)
	assert.Equal(t, "child", r.Description)
	r, _, err = c.roleStore.Get(rootCtx(), "deploy")
	require.NoError(t, err)
	assert.Equal(t, "", r.Description)
}

func TestRoles_CAS(t *testing.T) {
	c := createTestCore(t)
	ctx := rootCtx()

	resp := roleRequest(t, c, ctx, logical.CreateOperation, "roles/deploy", map[string]any{"description": "v1"})
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	h1 := resp.Data["hash"].(string)

	resp = roleRequest(t, c, ctx, logical.UpdateOperation, "roles/deploy", map[string]any{
		"description":   "v2",
		"expected_hash": h1,
	})
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v", resp.Err)
	h2 := resp.Data["hash"].(string)

	// A writer still holding the first read loses.
	resp = roleRequest(t, c, ctx, logical.UpdateOperation, "roles/deploy", map[string]any{
		"description":   "stale",
		"expected_hash": h1,
	})
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	r, hash, err := c.roleStore.Get(ctx, "deploy")
	require.NoError(t, err)
	assert.Equal(t, "v2", r.Description, "a refused write changes nothing")
	assert.Equal(t, h2, hash)

	resp = roleRequest(t, c, ctx, logical.DeleteOperation, "roles/deploy", map[string]any{"expected_hash": h1})
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	resp = roleRequest(t, c, ctx, logical.DeleteOperation, "roles/deploy", map[string]any{"expected_hash": h2})
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// The store itself refuses a write built on a version that has since changed,
	// which is what keeps an update's read-merge-write from undoing a concurrent one.
	_, err = c.roleStore.Create(ctx, &logical.Role{Name: "ops", Description: "a"})
	require.NoError(t, err)
	_, base, err := c.roleStore.Get(ctx, "ops")
	require.NoError(t, err)
	_, err = c.roleStore.Update(ctx, &logical.Role{Name: "ops", Description: "b"}, base)
	require.NoError(t, err)
	_, err = c.roleStore.Update(ctx, &logical.Role{Name: "ops", Description: "c"}, base)
	assert.ErrorIs(t, err, ErrRoleChanged)
}

func TestRoles_NameCharset(t *testing.T) {
	c := createTestCore(t)
	ctx := rootCtx()

	for _, name := range []string{"deploy", "a", "deploy-prod", "deploy.v2", "x_1"} {
		_, err := c.roleStore.Create(ctx, &logical.Role{Name: name})
		assert.NoError(t, err, name)
	}
	for _, name := range []string{"", "-deploy", "deploy-", "de/ploy", "de ploy", ".x", "dé"} {
		_, err := c.roleStore.Create(ctx, &logical.Role{Name: name})
		assert.Error(t, err, "%q must be refused", name)
		assert.Equal(t, http.StatusBadRequest, logical.GetErrorCode(err), name)
	}

	// The path pattern refuses a name with a "/" before any handler runs.
	_, err := c.systemBackend.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/de/ploy",
	})
	assert.Error(t, err)
}

// TestRoles_RootPolicyRefused: a role can never hand out the root policy. The
// non-assignable list is covered by logical.ValidateAssignablePolicies' own
// tests, and the structural test below pins the role write to that check.
func TestRoles_RootPolicyRefused(t *testing.T) {
	c := createTestCore(t)
	ctx := rootCtx()

	resp := roleRequest(t, c, ctx, logical.CreateOperation, "roles/admin", map[string]any{
		"policies": []any{"deploy", "root"},
	})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, resp.Err.Error(), `"root"`)
	_, _, err := c.roleStore.Get(ctx, "admin")
	assert.ErrorIs(t, err, ErrRoleNotFound, "nothing is stored")

	// Normalization runs first, so a disguised root is refused too.
	_, err = c.roleStore.Create(ctx, &logical.Role{Name: "admin", Policies: []string{" ROOT "}})
	assert.Error(t, err)

	// An update cannot add it either.
	_, err = c.roleStore.Create(ctx, &logical.Role{Name: "ops"})
	require.NoError(t, err)
	resp = roleRequest(t, c, ctx, logical.UpdateOperation, "roles/ops", map[string]any{"policies": []any{"root"}})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	r, _, err := c.roleStore.Get(ctx, "ops")
	require.NoError(t, err)
	assert.Empty(t, r.Policies)
}

// TestValidateAssignablePolicies_CalledFromBothSites pins the one policy check
// to both places that hand policies to a caller: a login and a role write. A
// second, drifting copy of the check at either site would fail it.
func TestValidateAssignablePolicies_CalledFromBothSites(t *testing.T) {
	calls := func(file, fn string) bool {
		t.Helper()
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, file, nil, 0)
		require.NoError(t, err)
		found := false
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Name.Name != fn {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "logical" && sel.Sel.Name == "ValidateAssignablePolicies" {
					found = true
				}
				return true
			})
		}
		return found
	}
	assert.True(t, calls("request_handler.go", "LoginCreateToken"),
		"LoginCreateToken must refuse root and non-assignable policies through logical.ValidateAssignablePolicies")
	assert.True(t, calls("role_store.go", "validateRole"),
		"a role write must refuse root and non-assignable policies through logical.ValidateAssignablePolicies")
}

func TestRoles_MissingPolicyAndSpecWarn(t *testing.T) {
	c := createTestCore(t)
	ctx := rootCtx()

	resp := roleRequest(t, c, ctx, logical.CreateOperation, "roles/deploy", map[string]any{
		"policies":       []any{"deploy"},
		"cred_spec_name": "deploy-role",
	})
	require.Equal(t, http.StatusCreated, resp.StatusCode, "a missing policy or spec is stored, not refused")
	assert.ElementsMatch(t, []string{
		`policy "deploy" does not exist yet`,
		`credential spec "deploy-role" does not exist yet`,
	}, respWarnings(resp))

	p := testParsePolicy(t, `path "aws/*" { capabilities = ["read"] }`)
	p.Name = "deploy"
	p.Type = PolicyTypeCBP
	require.NoError(t, c.policyStore.SetPolicy(ctx, p, nil))
	require.NoError(t, c.credConfigStore.CreateSource(ctx, &credential.CredSource{Name: "src", Type: "local"}))
	require.NoError(t, c.credConfigStore.CreateSpec(ctx, &credential.CredSpec{
		Name:   "deploy-role",
		Type:   "github_token",
		Source: "src",
		MinTTL: time.Minute,
		MaxTTL: time.Hour,
		Config: credential.NewConfig(map[string]string{"token": "t"}),
	}))

	resp = roleRequest(t, c, ctx, logical.UpdateOperation, "roles/deploy", map[string]any{"description": "now they exist"})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Empty(t, respWarnings(resp))
}

func TestRoles_DiscoveryFieldValidation(t *testing.T) {
	c := createTestCore(t)
	ctx := rootCtx()

	cases := []struct {
		name string
		data map[string]any
	}{
		{"skill not a skill name", map[string]any{"skill": "Not_A_Skill"}},
		{"absolute provider_path", map[string]any{"provider_path": "/aws/"}},
		{"dot-dot segment", map[string]any{"provider_path": "aws/../vault/"}},
		{"empty segment", map[string]any{"provider_path": "aws//x/"}},
		{"provider_path too long", map[string]any{"provider_path": strings.Repeat("a", 300)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := roleRequest(t, c, ctx, logical.CreateOperation, "roles/r", tc.data)
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		})
	}

	resp := roleRequest(t, c, ctx, logical.CreateOperation, "roles/r", map[string]any{
		"skill":         "aws",
		"provider_path": "team/aws",
	})
	require.Equal(t, http.StatusCreated, resp.StatusCode, "%v", resp.Err)
	assert.Equal(t, "team/aws/", resp.Data["provider_path"])
}

func TestRoles_Caps(t *testing.T) {
	c := createTestCore(t)
	ctx := rootCtx()

	_, err := c.roleStore.Create(ctx, &logical.Role{Name: "d", Description: strings.Repeat("x", logical.MaxRoleDescriptionBytes)})
	assert.NoError(t, err, "a description of exactly the cap is accepted")
	_, err = c.roleStore.Create(ctx, &logical.Role{Name: "d2", Description: strings.Repeat("x", logical.MaxRoleDescriptionBytes+1)})
	assert.Error(t, err)

	meta := map[string]string{}
	for i := range logical.MaxRoleMetadataKeys {
		meta[fmt.Sprintf("k%d", i)] = "v"
	}
	_, err = c.roleStore.Create(ctx, &logical.Role{Name: "m", Metadata: meta})
	assert.NoError(t, err, "metadata of exactly the cap is accepted")
	meta["one-more"] = "v"
	_, err = c.roleStore.Create(ctx, &logical.Role{Name: "m2", Metadata: meta})
	assert.Error(t, err)
	_, err = c.roleStore.Create(ctx, &logical.Role{Name: "m3", Metadata: map[string]string{"": "v"}})
	assert.Error(t, err, "an empty metadata key is refused")
	_, err = c.roleStore.Create(ctx, &logical.Role{Name: "p", Policies: []string{"a", " "}})
	assert.Error(t, err, "an empty policy name is refused")

	// No limit on the number of roles.
	for i := range 300 {
		_, err := c.roleStore.Create(ctx, &logical.Role{Name: fmt.Sprintf("bulk-%d", i)})
		require.NoError(t, err)
	}
}

// TestRoles_SnapshotImmutableAcrossPublish holds an old snapshot across writes:
// it must keep answering what it held, and roles handed out must not alias it.
func TestRoles_SnapshotImmutableAcrossPublish(t *testing.T) {
	c := createTestCore(t)
	ctx := rootCtx()
	other := namespace.ContextWithNamespace(context.Background(),
		&namespace.Namespace{ID: "other-ns", UUID: "other-ns-uuid", Path: "other/"})

	_, err := c.roleStore.Create(ctx, &logical.Role{Name: "deploy", Policies: []string{"a"}})
	require.NoError(t, err)
	_, err = c.roleStore.Create(other, &logical.Role{Name: "x"})
	require.NoError(t, err)

	old := c.roleStore.snapshot.Load()
	oldOther := old.byNS["other-ns"]

	_, err = c.roleStore.Update(ctx, &logical.Role{Name: "deploy", Policies: []string{"b"}}, "")
	require.NoError(t, err)
	_, err = c.roleStore.Create(ctx, &logical.Role{Name: "new"})
	require.NoError(t, err)

	e := old.lookup(namespace.RootNamespaceID, "deploy")
	require.NotNil(t, e)
	assert.Equal(t, []string{"a"}, e.role.Policies, "a reader of the old snapshot still sees the old role")
	assert.Nil(t, old.lookup(namespace.RootNamespaceID, "new"), "nor does it see later creates")

	cur := c.roleStore.snapshot.Load()
	assert.Equal(t, []string{"b"}, cur.lookup(namespace.RootNamespaceID, "deploy").role.Policies)
	assert.Same(t, oldOther, cur.byNS["other-ns"], "a write in one namespace shares the others by pointer")

	// A role handed out is a copy: changing it changes nothing published.
	r, _, err := c.roleStore.Get(ctx, "deploy")
	require.NoError(t, err)
	r.Policies[0] = "mutated"
	r.Description = "mutated"
	r2, _, err := c.roleStore.Get(ctx, "deploy")
	require.NoError(t, err)
	assert.Equal(t, []string{"b"}, r2.Policies)
	assert.Equal(t, "", r2.Description)

	// So is the caller's value after a write: the store keeps its own copy.
	in := &logical.Role{Name: "mine", Policies: []string{"p"}}
	_, err = c.roleStore.Create(ctx, in)
	require.NoError(t, err)
	in.Policies[0] = "mutated"
	r3, _, err := c.roleStore.Get(ctx, "mine")
	require.NoError(t, err)
	assert.Equal(t, []string{"p"}, r3.Policies)
}

// TestRoles_ConcurrentReadsDuringWrites runs lock-free readers against writers;
// run with -race. Every read sees a whole role: its policies always match the
// description it was written with.
func TestRoles_ConcurrentReadsDuringWrites(t *testing.T) {
	c := createTestCore(t)
	ctx := rootCtx()
	_, err := c.roleStore.Create(ctx, &logical.Role{Name: "deploy", Description: "0", Policies: []string{"p0"}})
	require.NoError(t, err)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if e := c.roleStore.snapshot.Load().lookup(namespace.RootNamespaceID, "deploy"); e != nil {
					if want := "p" + e.role.Description; len(e.role.Policies) != 1 || e.role.Policies[0] != want {
						t.Errorf("torn role: description %q, policies %v", e.role.Description, e.role.Policies)
						return
					}
				}
				if _, err := c.roleStore.List(ctx); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}

	for i := 1; i <= 200; i++ {
		_, err := c.roleStore.Update(ctx, &logical.Role{
			Name:        "deploy",
			Description: fmt.Sprint(i),
			Policies:    []string{fmt.Sprintf("p%d", i)},
		}, "")
		require.NoError(t, err)
		_, err = c.roleStore.Create(ctx, &logical.Role{Name: fmt.Sprintf("r%d", i)})
		require.NoError(t, err)
	}
	close(stop)
	wg.Wait()

	roles, err := c.roleStore.List(ctx)
	require.NoError(t, err)
	assert.Len(t, roles, 201)
}

// TestRoles_LoadFromStorage covers a restart: the snapshot is rebuilt from
// storage, a record that does not decode is skipped (it reads as not found), and
// roles stored for a namespace that no longer exists are skipped.
func TestRoles_LoadFromStorage(t *testing.T) {
	c := createTestCore(t)
	ctx := rootCtx()

	_, err := c.roleStore.Create(ctx, &logical.Role{Name: "deploy", Policies: []string{"deploy"}, ProviderPath: "aws/"})
	require.NoError(t, err)
	_, wantHash, err := c.roleStore.Get(ctx, "deploy")
	require.NoError(t, err)

	view := c.roleStore.storage
	require.NoError(t, view.Put(ctx, &sdklogical.StorageEntry{Key: roleStorageKey(namespace.RootNamespaceUUID, "broken"), Value: []byte("{")}))
	require.NoError(t, view.Put(ctx, &sdklogical.StorageEntry{Key: roleStorageKey("gone-ns-uuid", "orphan"), Value: []byte(`{"version":1,"role":{"name":"orphan"}}`)}))

	c.teardownRoleStore()
	_, _, err = c.roleStore.Get(ctx, "deploy")
	assert.ErrorIs(t, err, ErrRoleNotFound, "an unloaded store serves nothing")
	_, err = c.roleStore.Create(ctx, &logical.Role{Name: "x"})
	assert.ErrorIs(t, err, ErrRoleStoreNotLoaded, "an unloaded store refuses writes")

	require.NoError(t, c.setupRoleStore(ctx, false))
	r, hash, err := c.roleStore.Get(ctx, "deploy")
	require.NoError(t, err)
	assert.Equal(t, []string{"deploy"}, r.Policies)
	assert.Equal(t, "aws/", r.ProviderPath)
	assert.Equal(t, wantHash, hash)
	_, _, err = c.roleStore.Get(ctx, "broken")
	assert.ErrorIs(t, err, ErrRoleNotFound)

	// setupRoleStore on a standby loads nothing.
	c.teardownRoleStore()
	require.NoError(t, c.setupRoleStore(ctx, true))
	_, _, err = c.roleStore.Get(ctx, "deploy")
	assert.ErrorIs(t, err, ErrRoleNotFound)
}

// TestRoles_LoadActiveOnly: roles load on the active node only, and a failover
// rebuilds them on the new active node.
func TestRoles_LoadActiveOnly(t *testing.T) {
	origSleep := manualStepDownSleepPeriod
	manualStepDownSleepPeriod = 100 * time.Millisecond
	defer func() { manualStepDownSleepPeriod = origSleep }()

	active, standby, core1, core2, _ := setupTwoNodeHA(t)
	defer core1.Shutdown()
	defer core2.Shutdown()
	ctx := rootCtx()

	_, err := active.roleStore.Create(ctx, &logical.Role{Name: "deploy", Policies: []string{"deploy"}})
	require.NoError(t, err)

	_, _, err = standby.roleStore.Get(ctx, "deploy")
	assert.ErrorIs(t, err, ErrRoleNotFound, "a standby holds no roles")
	_, err = standby.roleStore.Create(ctx, &logical.Role{Name: "other"})
	assert.ErrorIs(t, err, ErrRoleStoreNotLoaded, "a standby takes no role writes")

	require.NoError(t, active.StepDown(nil))
	promoted := waitForActiveNode(t, []*Core{standby}, 10*time.Second)
	require.Same(t, standby, promoted)

	require.Eventually(t, func() bool {
		r, _, err := promoted.roleStore.Get(ctx, "deploy")
		return err == nil && len(r.Policies) == 1 && r.Policies[0] == "deploy"
	}, 5*time.Second, 20*time.Millisecond, "the new active node loads the roles")

	require.Eventually(t, func() bool {
		_, _, err := active.roleStore.Get(ctx, "deploy")
		return err != nil
	}, 5*time.Second, 20*time.Millisecond, "the node that stepped down drops its snapshot")
}

func TestRoles_ClearNamespace(t *testing.T) {
	c := createTestCore(t)
	child := &namespace.Namespace{ID: "clear-ns", UUID: "clear-ns-uuid", Path: "clear/"}
	childCtx := namespace.ContextWithNamespace(context.Background(), child)

	for _, n := range []string{"a", "b"} {
		_, err := c.roleStore.Create(childCtx, &logical.Role{Name: n})
		require.NoError(t, err)
	}
	_, err := c.roleStore.Create(rootCtx(), &logical.Role{Name: "keep"})
	require.NoError(t, err)

	require.NoError(t, c.namespaceStore.clearNamespaceResources(childCtx, child))

	roles, err := c.roleStore.List(childCtx)
	require.NoError(t, err)
	assert.Empty(t, roles)
	keys, err := c.roleStore.storage.List(context.Background(), roleListPrefix(child.UUID))
	require.NoError(t, err)
	assert.Empty(t, keys, "the namespace's records are deleted from storage")

	_, _, err = c.roleStore.Get(rootCtx(), "keep")
	assert.NoError(t, err, "other namespaces keep their roles")
}

// TestRoles_SudoRequired: every role path is a root path, so the policy check
// refuses a token without sudo however broad its other capabilities.
func TestRoles_SudoRequired(t *testing.T) {
	c := createTestCore(t)
	ctx := rootCtx()

	for _, p := range []string{"sys/roles", "sys/roles/", "sys/roles/deploy"} {
		assert.True(t, c.router.RootPath(ctx, p), "%s must require sudo", p)
	}
	assert.False(t, c.router.RootPath(ctx, "sys/introspect/roles"), "discovery stays open")

	for _, tc := range []struct {
		op   logical.Operation
		path string
	}{
		{logical.CreateOperation, "sys/roles/deploy"},
		{logical.ReadOperation, "sys/roles/deploy"},
		{logical.UpdateOperation, "sys/roles/deploy"},
		{logical.DeleteOperation, "sys/roles/deploy"},
		{logical.ListOperation, "sys/roles"},
	} {
		req := &logical.Request{Operation: tc.op, Path: tc.path}

		noSudo, err := NewCBP(ctx, []*Policy{testParsePolicy(t,
			`path "sys/roles" { capabilities = ["list"] }
			 path "sys/roles/*" { capabilities = ["create", "read", "update", "delete", "list"] }`)})
		require.NoError(t, err)
		res := c.performPolicyChecks(ctx, noSudo, nil, req, &PolicyCheckOpts{RootPrivsRequired: c.router.RootPath(ctx, tc.path)})
		assert.False(t, res.Allowed, "%s %s without sudo must be refused", tc.op, tc.path)

		withSudo, err := NewCBP(ctx, []*Policy{testParsePolicy(t,
			`path "sys/roles" { capabilities = ["list", "sudo"] }
			 path "sys/roles/*" { capabilities = ["create", "read", "update", "delete", "list", "sudo"] }`)})
		require.NoError(t, err)
		res = c.performPolicyChecks(ctx, withSudo, nil, req, &PolicyCheckOpts{RootPrivsRequired: c.router.RootPath(ctx, tc.path)})
		assert.True(t, res.Allowed, "%s %s with sudo must be allowed", tc.op, tc.path)
	}
}
