package core

import (
	"net/http"
	"testing"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSystemBackend_PathProviders(t *testing.T) {
	backend, _, _ := setupTestSystemBackend(t)

	paths := backend.pathProviders()
	require.Len(t, paths, 2)

	// Check providers/{path} path
	assert.Equal(t, "providers/"+framework.MatchAllRegex("path"), paths[0].Pattern)
	assert.Contains(t, paths[0].Fields, "path")
	assert.Contains(t, paths[0].Fields, "type")
	assert.Contains(t, paths[0].Fields, "description")
	assert.Contains(t, paths[0].Fields, "config")

	// Check providers/ list path
	assert.Equal(t, "providers/?$", paths[1].Pattern)
}

func TestSystemBackend_HandleProviderCreate(t *testing.T) {
	backend, ctx, core := setupTestSystemBackend(t)

	// Register mock provider factory
	core.providers["mock"] = MockProviderFactory

	schema := backend.pathProviders()[0].Fields
	raw := map[string]interface{}{
		"path":        "test-provider",
		"type":        "mock",
		"description": "Test provider",
		"config":      map[string]interface{}{"key": "value"},
	}

	req := createTestRequest(logical.CreateOperation, "providers/test-provider", raw)
	fieldData := createFieldData(schema, raw)

	resp, err := backend.handleProviderCreate(ctx, req, fieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Contains(t, resp.Data, "accessor")
	assert.Equal(t, "test-provider/", resp.Data["path"])
}

func TestSystemBackend_HandleProviderCreate_InvalidPath(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)

	schema := backend.pathProviders()[0].Fields
	raw := map[string]interface{}{
		"path": "sys/invalid", // Reserved path
		"type": "mock",
	}

	req := createTestRequest(logical.CreateOperation, "providers/sys/invalid", raw)
	fieldData := createFieldData(schema, raw)

	resp, err := backend.handleProviderCreate(ctx, req, fieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestSystemBackend_HandleProviderRead(t *testing.T) {
	backend, ctx, core := setupTestSystemBackend(t)

	// First create a provider mount
	core.providers["mock"] = MockProviderFactory

	entry := &MountEntry{
		Class:       mountClassProvider,
		Type:        "mock",
		Path:        "test-provider/",
		Description: "Test provider",
	}
	err := core.mount(ctx, entry)
	require.NoError(t, err)

	// Now read it
	schema := backend.pathProviders()[0].Fields
	raw := map[string]interface{}{
		"path": "test-provider",
	}

	req := createTestRequest(logical.ReadOperation, "providers/test-provider", raw)
	fieldData := createFieldData(schema, raw)

	resp, err := backend.handleProviderRead(ctx, req, fieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "mock", resp.Data["type"])
	assert.Equal(t, "test-provider/", resp.Data["path"])
}

func TestSystemBackend_HandleProviderRead_NotFound(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)

	schema := backend.pathProviders()[0].Fields
	raw := map[string]interface{}{
		"path": "nonexistent",
	}

	req := createTestRequest(logical.ReadOperation, "providers/nonexistent", raw)
	fieldData := createFieldData(schema, raw)

	resp, err := backend.handleProviderRead(ctx, req, fieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestSystemBackend_HandleProviderDelete(t *testing.T) {
	backend, ctx, core := setupTestSystemBackend(t)

	// First create a provider mount
	core.providers["mock"] = MockProviderFactory

	entry := &MountEntry{
		Class:       mountClassProvider,
		Type:        "mock",
		Path:        "test-provider/",
		Description: "Test provider",
	}
	err := core.mount(ctx, entry)
	require.NoError(t, err)

	// Now delete it
	schema := backend.pathProviders()[0].Fields
	raw := map[string]interface{}{
		"path": "test-provider",
	}

	req := createTestRequest(logical.DeleteOperation, "providers/test-provider", raw)
	fieldData := createFieldData(schema, raw)

	resp, err := backend.handleProviderDelete(ctx, req, fieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Data["message"], "Successfully unmounted")
}

func TestSystemBackend_HandleProviderList(t *testing.T) {
	backend, ctx, core := setupTestSystemBackend(t)

	// Create provider mounts
	core.providers["mock"] = MockProviderFactory

	entry1 := &MountEntry{
		Class:       mountClassProvider,
		Type:        "mock",
		Path:        "provider1/",
		Description: "Provider 1",
	}
	entry2 := &MountEntry{
		Class:       mountClassProvider,
		Type:        "mock",
		Path:        "provider2/",
		Description: "Provider 2",
	}
	require.NoError(t, core.mount(ctx, entry1))
	require.NoError(t, core.mount(ctx, entry2))

	// List provider mounts
	schema := backend.pathProviders()[1].Fields
	raw := map[string]interface{}{}

	req := createTestRequest(logical.ListOperation, "providers/", raw)
	fieldData := createFieldData(schema, raw)

	resp, err := backend.handleProviderList(ctx, req, fieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	mounts, ok := resp.Data["mounts"].(map[string]any)
	require.True(t, ok)
	assert.Len(t, mounts, 2)
}
