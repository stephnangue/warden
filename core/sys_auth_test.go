package core

import (
	"net/http"
	"testing"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSystemBackend_PathAuth(t *testing.T) {
	backend, _, _ := setupTestSystemBackend(t)

	paths := backend.pathAuth()
	require.Len(t, paths, 2)

	// Check auth/{path} path
	assert.Equal(t, "auth/"+framework.MatchAllRegex("path"), paths[0].Pattern)
	assert.Contains(t, paths[0].Fields, "path")
	assert.Contains(t, paths[0].Fields, "type")
	assert.Contains(t, paths[0].Fields, "description")
	assert.Contains(t, paths[0].Fields, "config")

	// Check auth/ list path
	assert.Equal(t, "auth/?$", paths[1].Pattern)
}

func TestSystemBackend_HandleAuthCreate(t *testing.T) {
	backend, ctx, core := setupTestSystemBackend(t)

	// Register mock auth backend factory
	core.authMethods["mock"] = MockProviderFactory

	schema := backend.pathAuth()[0].Fields
	raw := map[string]interface{}{
		"path":        "test-auth",
		"type":        "mock",
		"description": "Test auth method",
		"config":      map[string]interface{}{"key": "value"},
	}

	req := createTestRequest(logical.CreateOperation, "auth/test-auth", raw)
	fieldData := createFieldData(schema, raw)

	resp, err := backend.handleAuthCreate(ctx, req, fieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Contains(t, resp.Data, "accessor")
	assert.Equal(t, "test-auth/", resp.Data["path"])
}

func TestSystemBackend_HandleAuthCreate_UnsupportedType(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)

	schema := backend.pathAuth()[0].Fields
	raw := map[string]interface{}{
		"path": "test-auth",
		"type": "unsupported",
	}

	req := createTestRequest(logical.CreateOperation, "auth/test-auth", raw)
	fieldData := createFieldData(schema, raw)

	resp, err := backend.handleAuthCreate(ctx, req, fieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotEqual(t, http.StatusCreated, resp.StatusCode)
}

func TestSystemBackend_HandleAuthRead(t *testing.T) {
	backend, ctx, core := setupTestSystemBackend(t)

	// First create an auth mount
	core.authMethods["mock"] = MockProviderFactory

	entry := &MountEntry{
		Class:       mountClassAuth,
		Type:        "mock",
		Path:        "test-auth/",
		Description: "Test auth",
	}
	err := core.mount(ctx, entry)
	require.NoError(t, err)

	// Now read it
	schema := backend.pathAuth()[0].Fields
	raw := map[string]interface{}{
		"path": "test-auth",
	}

	req := createTestRequest(logical.ReadOperation, "auth/test-auth", raw)
	fieldData := createFieldData(schema, raw)

	resp, err := backend.handleAuthRead(ctx, req, fieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "mock", resp.Data["type"])
	assert.Equal(t, "test-auth/", resp.Data["path"])
}

func TestSystemBackend_HandleAuthRead_NotFound(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)

	schema := backend.pathAuth()[0].Fields
	raw := map[string]interface{}{
		"path": "nonexistent",
	}

	req := createTestRequest(logical.ReadOperation, "auth/nonexistent", raw)
	fieldData := createFieldData(schema, raw)

	resp, err := backend.handleAuthRead(ctx, req, fieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestSystemBackend_HandleAuthDelete(t *testing.T) {
	backend, ctx, core := setupTestSystemBackend(t)

	// First create an auth mount
	core.authMethods["mock"] = MockProviderFactory

	entry := &MountEntry{
		Class:       mountClassAuth,
		Type:        "mock",
		Path:        "test-auth/",
		Description: "Test auth",
	}
	err := core.mount(ctx, entry)
	require.NoError(t, err)

	// Now delete it
	schema := backend.pathAuth()[0].Fields
	raw := map[string]interface{}{
		"path": "test-auth",
	}

	req := createTestRequest(logical.DeleteOperation, "auth/test-auth", raw)
	fieldData := createFieldData(schema, raw)

	resp, err := backend.handleAuthDelete(ctx, req, fieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Data["message"], "Successfully unmounted")
}

func TestSystemBackend_HandleAuthList(t *testing.T) {
	backend, ctx, core := setupTestSystemBackend(t)

	// Create auth mounts
	core.authMethods["mock"] = MockProviderFactory

	entry1 := &MountEntry{
		Class:       mountClassAuth,
		Type:        "mock",
		Path:        "auth1/",
		Description: "Auth 1",
	}
	entry2 := &MountEntry{
		Class:       mountClassAuth,
		Type:        "mock",
		Path:        "auth2/",
		Description: "Auth 2",
	}
	require.NoError(t, core.mount(ctx, entry1))
	require.NoError(t, core.mount(ctx, entry2))

	// List auth mounts
	schema := backend.pathAuth()[1].Fields
	raw := map[string]interface{}{}

	req := createTestRequest(logical.ListOperation, "auth/", raw)
	fieldData := createFieldData(schema, raw)

	resp, err := backend.handleAuthList(ctx, req, fieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	mounts, ok := resp.Data["mounts"].(map[string]any)
	require.True(t, ok)
	assert.Len(t, mounts, 2)
}
