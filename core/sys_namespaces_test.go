package core

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSystemBackend_PathNamespaces(t *testing.T) {
	backend, _, _ := setupTestSystemBackend(t)

	paths := backend.pathNamespaces()
	require.Len(t, paths, 2)

	// Check namespaces/{path} path
	assert.Equal(t, "namespaces/"+framework.MatchAllRegex("path"), paths[0].Pattern)
	assert.Contains(t, paths[0].Fields, "path")
	assert.Contains(t, paths[0].Fields, "custom_metadata")

	// Check namespaces/ list path
	assert.Equal(t, "namespaces/?$", paths[1].Pattern)
	assert.Contains(t, paths[1].Fields, "recursive")
	assert.Contains(t, paths[1].Fields, "include_parent")
}

func TestSystemBackend_HandleNamespaceCreate(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)

	schema := backend.pathNamespaces()[0].Fields
	raw := map[string]interface{}{
		"path":            "test-ns",
		"custom_metadata": map[string]interface{}{"env": "test"},
	}

	req := createTestRequest(logical.CreateOperation, "namespaces/test-ns", raw)
	fieldData := createFieldData(schema, raw)

	resp, err := backend.handleNamespaceCreate(ctx, req, fieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Contains(t, resp.Data, "id")
	assert.Equal(t, "test-ns/", resp.Data["path"])
}

func TestSystemBackend_HandleNamespaceRead(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)

	// First create a namespace
	schema := backend.pathNamespaces()[0].Fields
	raw := map[string]interface{}{
		"path": "test-ns",
	}

	req := createTestRequest(logical.CreateOperation, "namespaces/test-ns", raw)
	fieldData := createFieldData(schema, raw)

	_, err := backend.handleNamespaceCreate(ctx, req, fieldData)
	require.NoError(t, err)

	// Now read it
	resp, err := backend.handleNamespaceRead(ctx, req, fieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "test-ns/", resp.Data["path"])
}

func TestSystemBackend_HandleNamespaceRead_NotFound(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)

	schema := backend.pathNamespaces()[0].Fields
	raw := map[string]interface{}{
		"path": "nonexistent",
	}

	req := createTestRequest(logical.ReadOperation, "namespaces/nonexistent", raw)
	fieldData := createFieldData(schema, raw)

	resp, err := backend.handleNamespaceRead(ctx, req, fieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestSystemBackend_HandleNamespaceUpdate(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)

	// First create a namespace
	schema := backend.pathNamespaces()[0].Fields
	createRaw := map[string]interface{}{
		"path":            "test-ns",
		"custom_metadata": map[string]interface{}{"env": "test"},
	}

	req := createTestRequest(logical.CreateOperation, "namespaces/test-ns", createRaw)
	fieldData := createFieldData(schema, createRaw)

	_, err := backend.handleNamespaceCreate(ctx, req, fieldData)
	require.NoError(t, err)

	// Now update it
	updateRaw := map[string]interface{}{
		"path":            "test-ns",
		"custom_metadata": map[string]interface{}{"env": "production"},
	}
	fieldData = createFieldData(schema, updateRaw)

	resp, err := backend.handleNamespaceUpdate(ctx, req, fieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Data["message"], "Successfully updated")
}

func TestSystemBackend_HandleNamespaceDelete(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)

	// First create a namespace
	schema := backend.pathNamespaces()[0].Fields
	raw := map[string]interface{}{
		"path": "test-ns",
	}

	req := createTestRequest(logical.CreateOperation, "namespaces/test-ns", raw)
	fieldData := createFieldData(schema, raw)

	_, err := backend.handleNamespaceCreate(ctx, req, fieldData)
	require.NoError(t, err)

	// Now delete it
	resp, err := backend.handleNamespaceDelete(ctx, req, fieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestSystemBackend_HandleNamespaceList(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)

	// Create some namespaces
	schema := backend.pathNamespaces()[0].Fields
	for _, ns := range []string{"ns1", "ns2", "ns3"} {
		raw := map[string]interface{}{"path": ns}
		fieldData := createFieldData(schema, raw)
		req := createTestRequest(logical.CreateOperation, "namespaces/"+ns, raw)
		_, err := backend.handleNamespaceCreate(ctx, req, fieldData)
		require.NoError(t, err)
	}

	// List namespaces
	listSchema := backend.pathNamespaces()[1].Fields
	listRaw := map[string]interface{}{
		"recursive":      false,
		"include_parent": false,
	}
	req := createTestRequest(logical.ListOperation, "namespaces/", listRaw)
	fieldData := createFieldData(listSchema, listRaw)

	resp, err := backend.handleNamespaceList(ctx, req, fieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Check keys field
	keys, ok := resp.Data["keys"].([]string)
	require.True(t, ok)
	assert.Len(t, keys, 3)

	// Check namespaces field for detailed info
	namespaces, ok := resp.Data["namespaces"].([]map[string]any)
	require.True(t, ok)
	assert.Len(t, namespaces, 3)
}

// nsWrite runs a create or an update of sys/namespaces/<path> in ctx.
func nsWrite(t *testing.T, b *SystemBackend, ctx context.Context, op logical.Operation, path string, raw map[string]any) *logical.Response {
	t.Helper()
	raw["path"] = path
	d := createFieldData(b.pathNamespaces()[0].Fields, raw)
	req := createTestRequest(op, "namespaces/"+path, raw)
	var resp *logical.Response
	var err error
	if op == logical.CreateOperation {
		resp, err = b.handleNamespaceCreate(ctx, req, d)
	} else {
		resp, err = b.handleNamespaceUpdate(ctx, req, d)
	}
	require.NoError(t, err)
	require.NotNil(t, resp)
	return resp
}

func TestSystemBackend_NamespaceEnableBuiltinRoles(t *testing.T) {
	b, ctx, c := setupTestSystemBackend(t)

	resp := nsWrite(t, b, ctx, logical.CreateOperation, "acme", map[string]any{"enable_builtin_roles": true})
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Equal(t, true, resp.Data["enable_builtin_roles"])
	acme, err := c.namespaceStore.GetNamespaceByPath(ctx, "acme")
	require.NoError(t, err)
	assert.True(t, acme.EnableBuiltinRoles)

	// A child does not inherit it. Created from its parent: a nested path
	// written from root lands in root's storage view.
	acmeCtx := namespace.ContextWithNamespace(context.Background(), acme)
	nsWrite(t, b, acmeCtx, logical.CreateOperation, "dev", map[string]any{})
	dev, err := c.namespaceStore.GetNamespaceByPath(ctx, "acme/dev")
	require.NoError(t, err)
	assert.False(t, dev.EnableBuiltinRoles)

	// An update that does not name it leaves it as it is.
	nsWrite(t, b, ctx, logical.UpdateOperation, "acme", map[string]any{"custom_metadata": map[string]any{"env": "prod"}})
	acme, err = c.namespaceStore.GetNamespaceByPath(ctx, "acme")
	require.NoError(t, err)
	assert.True(t, acme.EnableBuiltinRoles)

	// Read and list render it.
	read, err := b.handleNamespaceRead(ctx, createTestRequest(logical.ReadOperation, "namespaces/acme", nil),
		createFieldData(b.pathNamespaces()[0].Fields, map[string]any{"path": "acme"}))
	require.NoError(t, err)
	assert.Equal(t, true, read.Data["enable_builtin_roles"])
	list, err := b.handleNamespaceList(ctx, createTestRequest(logical.ListOperation, "namespaces", nil),
		createFieldData(b.pathNamespaces()[1].Fields, map[string]any{"recursive": true}))
	require.NoError(t, err)
	byPath := map[string]any{}
	for _, info := range list.Data["namespaces"].([]map[string]any) {
		byPath[info["path"].(string)] = info["enable_builtin_roles"]
	}
	assert.Equal(t, true, byPath["acme/"])
	assert.Equal(t, false, byPath["acme/dev/"])
	withRoot, err := b.handleNamespaceList(ctx, createTestRequest(logical.ListOperation, "namespaces", nil),
		createFieldData(b.pathNamespaces()[1].Fields, map[string]any{"include_parent": true}))
	require.NoError(t, err)
	sawRoot := false
	for _, info := range withRoot.Data["namespaces"].([]map[string]any) {
		if info["path"] == "" {
			sawRoot = true
			assert.Equal(t, true, info["enable_builtin_roles"], "root has them whatever its record says")
		}
	}
	assert.True(t, sawRoot, "include_parent lists root")

	// Off and on again.
	resp = nsWrite(t, b, ctx, logical.UpdateOperation, "acme", map[string]any{"enable_builtin_roles": false})
	assert.Equal(t, false, resp.Data["enable_builtin_roles"])
	resp = nsWrite(t, b, ctx, logical.UpdateOperation, "acme", map[string]any{"enable_builtin_roles": true})
	assert.Equal(t, true, resp.Data["enable_builtin_roles"])

	// The flag survives the record's trip through storage.
	c.namespaceStore.lock.Lock()
	err = c.namespaceStore.loadNamespacesLocked(ctx)
	c.namespaceStore.lock.Unlock()
	require.NoError(t, err)
	acme, err = c.namespaceStore.GetNamespaceByPath(ctx, "acme")
	require.NoError(t, err)
	assert.True(t, acme.EnableBuiltinRoles, "after a reload from storage")
}

// Turning the flag off is refused while a group of the namespace, virtual or
// static, grants a built-in: the refusal names each group, its type and the
// role, and the write goes through once they are gone.
func TestSystemBackend_NamespaceEnableBuiltinRoles_TurnOffRefused(t *testing.T) {
	b, ctx, c := setupTestSystemBackend(t)
	nsWrite(t, b, ctx, logical.CreateOperation, "acme", map[string]any{"enable_builtin_roles": true})
	acme, err := c.namespaceStore.GetNamespaceByPath(ctx, "acme")
	require.NoError(t, err)
	acmeCtx := namespace.ContextWithNamespace(context.Background(), acme)

	_, err = c.identityStore.CreateGroup(acmeCtx, virtualGroup("platform-admins", "warden-admin"))
	require.NoError(t, err)
	_, err = c.identityStore.CreateGroup(acmeCtx, &logical.Group{Name: "terraform-runners", Type: logical.GroupTypeStatic,
		Roles: []string{"deploy", "warden-provider-admin"}})
	require.NoError(t, err)
	_, err = c.identityStore.CreateGroup(acmeCtx, virtualGroup("deployers", "deploy"))
	require.NoError(t, err)

	resp := nsWrite(t, b, ctx, logical.UpdateOperation, "acme", map[string]any{"enable_builtin_roles": false})
	require.Error(t, resp.Error())
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, resp.Error().Error(), "enable_builtin_roles cannot be turned off: groups still grant built-in roles: "+
		"platform-admins (virtual, warden-admin), terraform-runners (static, warden-provider-admin)")
	assert.NotContains(t, resp.Error().Error(), "deployers")
	acme, err = c.namespaceStore.GetNamespaceByPath(ctx, "acme")
	require.NoError(t, err)
	assert.True(t, acme.EnableBuiltinRoles, "the refused write changed nothing")

	for _, g := range []struct {
		name string
		typ  logical.GroupType
	}{{"platform-admins", logical.GroupTypeVirtual}, {"terraform-runners", logical.GroupTypeStatic}} {
		_, err = c.identityStore.DeleteGroup(acmeCtx, g.name, g.typ, "", false)
		require.NoError(t, err)
	}
	resp = nsWrite(t, b, ctx, logical.UpdateOperation, "acme", map[string]any{"enable_builtin_roles": false})
	require.NoError(t, resp.Error())
	assert.Equal(t, false, resp.Data["enable_builtin_roles"])
}

// A namespace cannot reach its own record: every spelling of its own path
// from inside it names a child, or is refused, and never flips the flag of
// the namespace itself.
func TestSystemBackend_NamespaceEnableBuiltinRoles_NotFromInside(t *testing.T) {
	b, ctx, c := setupTestSystemBackend(t)
	nsWrite(t, b, ctx, logical.CreateOperation, "acme", map[string]any{})
	acme, err := c.namespaceStore.GetNamespaceByPath(ctx, "acme")
	require.NoError(t, err)
	acmeCtx := namespace.ContextWithNamespace(context.Background(), acme)

	for _, path := range []string{"", ".", "./", "..", "../acme", "acme"} {
		for _, op := range []logical.Operation{logical.CreateOperation, logical.UpdateOperation} {
			raw := map[string]any{"path": path, "enable_builtin_roles": true}
			d := createFieldData(b.pathNamespaces()[0].Fields, raw)
			req := createTestRequest(op, "namespaces/"+path, raw)
			if op == logical.CreateOperation {
				_, _ = b.handleNamespaceCreate(acmeCtx, req, d)
			} else {
				_, _ = b.handleNamespaceUpdate(acmeCtx, req, d)
			}
			got, err := c.namespaceStore.GetNamespaceByPath(ctx, "acme")
			require.NoError(t, err)
			assert.False(t, got.EnableBuiltinRoles, "%s %q from inside acme", op, path)

			// Whatever a write from inside wrote is below acme/, never acme/
			// or above it. ("." is a segment Validate accepts, so "." makes a
			// child named "acme/./"; over HTTP the router cleans it first.)
			all, err := c.namespaceStore.ListAllNamespaces(ctx, false)
			require.NoError(t, err)
			for _, n := range all {
				if n.Path == "acme/" {
					continue
				}
				assert.True(t, strings.HasPrefix(n.Path, "acme/"), "%s %q from inside acme wrote %q", op, path, n.Path)
			}
		}
	}
}
