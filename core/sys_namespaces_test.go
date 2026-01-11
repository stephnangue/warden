package core

import (
	"net/http"
	"testing"

	"github.com/stephnangue/warden/framework"
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

	namespaces, ok := resp.Data["namespaces"].([]map[string]any)
	require.True(t, ok)
	assert.Len(t, namespaces, 3)
}
