package core

import (
	"context"
	"net/http"
	"testing"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createHVaultSource is a helper that creates an hvault source for testing vault_token specs
func createHVaultSource(t *testing.T, backend *SystemBackend, ctx context.Context, name string) {
	t.Helper()
	sourceSchema := backend.pathCredentials()[0].Fields
	sourceRaw := map[string]interface{}{
		"name":            name,
		"type":            "hvault",
		"rotation_period": 86400, // 24 hours
		"config": map[string]interface{}{
			"vault_address": "http://localhost:8200",
		},
	}
	sourceReq := createTestRequest(logical.CreateOperation, "cred/sources/"+name, sourceRaw)
	sourceFieldData := createFieldData(sourceSchema, sourceRaw)
	resp, err := backend.handleCredentialSourceCreate(ctx, sourceReq, sourceFieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	if resp.Err != nil {
		t.Fatalf("Source creation failed: %v", resp.Err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Source creation returned status %d (expected 201), data: %+v", resp.StatusCode, resp.Data)
	}
}

func TestSystemBackend_PathCredentials(t *testing.T) {
	backend, _, _ := setupTestSystemBackend(t)

	paths := backend.pathCredentials()
	require.Len(t, paths, 4) // sources CRUD, sources list, specs CRUD, specs list

	// Check sources/{name} path
	assert.Equal(t, "cred/sources/"+framework.GenericNameRegex("name"), paths[0].Pattern)

	// Check sources/ list path
	assert.Equal(t, "cred/sources/?$", paths[1].Pattern)

	// Check specs/{name} path
	assert.Equal(t, "cred/specs/"+framework.GenericNameRegex("name"), paths[2].Pattern)

	// Check specs/ list path
	assert.Equal(t, "cred/specs/?$", paths[3].Pattern)
}

func TestSystemBackend_HandleCredentialSourceCreate(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)

	schema := backend.pathCredentials()[0].Fields
	raw := map[string]interface{}{
		"name":   "test-source",
		"type":   "local",
		"config": map[string]interface{}{"key": "value"},
	}

	req := createTestRequest(logical.CreateOperation, "cred/sources/test-source", raw)
	fieldData := createFieldData(schema, raw)

	resp, err := backend.handleCredentialSourceCreate(ctx, req, fieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Equal(t, "test-source", resp.Data["name"])
	assert.Equal(t, "local", resp.Data["type"])
}

func TestSystemBackend_HandleCredentialSourceRead(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)

	// First create a source
	schema := backend.pathCredentials()[0].Fields
	raw := map[string]interface{}{
		"name": "test-source",
		"type": "local",
	}

	req := createTestRequest(logical.CreateOperation, "cred/sources/test-source", raw)
	fieldData := createFieldData(schema, raw)

	_, err := backend.handleCredentialSourceCreate(ctx, req, fieldData)
	require.NoError(t, err)

	// Now read it
	resp, err := backend.handleCredentialSourceRead(ctx, req, fieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "test-source", resp.Data["name"])
}

func TestSystemBackend_HandleCredentialSourceUpdate(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)

	// First create a source
	schema := backend.pathCredentials()[0].Fields
	createRaw := map[string]interface{}{
		"name":   "test-source",
		"type":   "local",
		"config": map[string]interface{}{"key": "value1"},
	}

	req := createTestRequest(logical.CreateOperation, "cred/sources/test-source", createRaw)
	fieldData := createFieldData(schema, createRaw)

	_, err := backend.handleCredentialSourceCreate(ctx, req, fieldData)
	require.NoError(t, err)

	// Now update it
	updateRaw := map[string]interface{}{
		"name":   "test-source",
		"config": map[string]interface{}{"key": "value2"},
	}
	fieldData = createFieldData(schema, updateRaw)

	resp, err := backend.handleCredentialSourceUpdate(ctx, req, fieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Data["message"], "Successfully updated")
}

func TestSystemBackend_HandleCredentialSourceDelete(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)

	// First create a source
	schema := backend.pathCredentials()[0].Fields
	raw := map[string]interface{}{
		"name": "test-source",
		"type": "local",
	}

	req := createTestRequest(logical.CreateOperation, "cred/sources/test-source", raw)
	fieldData := createFieldData(schema, raw)

	_, err := backend.handleCredentialSourceCreate(ctx, req, fieldData)
	require.NoError(t, err)

	// Now delete it
	resp, err := backend.handleCredentialSourceDelete(ctx, req, fieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Data["message"], "Successfully deleted")
}

func TestSystemBackend_HandleCredentialSourceDelete_WithReferences(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)

	// Create hvault source (required for vault_token type)
	createHVaultSource(t, backend, ctx, "test-source")

	// Create a spec that references the source
	specSchema := backend.pathCredentials()[2].Fields
	specRaw := map[string]interface{}{
		"name":   "test-spec",
		"type":   "vault_token",
		"source": "test-source",
		"config": map[string]interface{}{
			"mint_method": "vault_token",
			"token_role":  "test-role",
		},
	}

	specReq := createTestRequest(logical.CreateOperation, "cred/specs/test-spec", specRaw)
	specFieldData := createFieldData(specSchema, specRaw)

	specResp, err := backend.handleCredentialSpecCreate(ctx, specReq, specFieldData)
	require.NoError(t, err)
	require.NotNil(t, specResp)
	if specResp.Err != nil {
		t.Fatalf("Spec creation failed: %v", specResp.Err)
	}
	if specResp.StatusCode != http.StatusCreated {
		t.Fatalf("Spec creation returned status %d, expected 201", specResp.StatusCode)
	}

	// Try to delete the source - should fail
	sourceSchema := backend.pathCredentials()[0].Fields
	sourceRaw := map[string]interface{}{
		"name": "test-source",
	}
	req := createTestRequest(logical.DeleteOperation, "cred/sources/test-source", sourceRaw)
	fieldData := createFieldData(sourceSchema, sourceRaw)

	resp, err := backend.handleCredentialSourceDelete(ctx, req, fieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotNil(t, resp.Err)
	assert.Contains(t, resp.Err.Error(), "still referenced")
}

func TestSystemBackend_HandleCredentialSourceList(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)

	// Create some sources
	schema := backend.pathCredentials()[0].Fields
	for _, name := range []string{"source1", "source2", "source3"} {
		raw := map[string]interface{}{
			"name": name,
			"type": "local",
		}
		fieldData := createFieldData(schema, raw)
		req := createTestRequest(logical.CreateOperation, "cred/sources/"+name, raw)
		_, err := backend.handleCredentialSourceCreate(ctx, req, fieldData)
		require.NoError(t, err)
	}

	// List sources
	listSchema := backend.pathCredentials()[1].Fields
	listRaw := map[string]interface{}{}
	req := createTestRequest(logical.ListOperation, "cred/sources/", listRaw)
	fieldData := createFieldData(listSchema, listRaw)

	resp, err := backend.handleCredentialSourceList(ctx, req, fieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	sources, ok := resp.Data["sources"].([]map[string]any)
	require.True(t, ok)
	// Expect 4 sources: 1 default "local" source + 3 created sources
	assert.Len(t, sources, 4)
}

func TestSystemBackend_HandleCredentialSpecCreate(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)

	// Create hvault source (required for vault_token type)
	createHVaultSource(t, backend, ctx, "test-source")

	// Now create a spec
	specSchema := backend.pathCredentials()[2].Fields
	specRaw := map[string]interface{}{
		"name":    "test-spec",
		"type":    "vault_token",
		"source":  "test-source",
		"min_ttl": 3600,
		"max_ttl": 86400,
		"config": map[string]interface{}{
			"mint_method": "vault_token",
			"token_role":  "test-role",
		},
	}

	specReq := createTestRequest(logical.CreateOperation, "cred/specs/test-spec", specRaw)
	specFieldData := createFieldData(specSchema, specRaw)

	resp, err := backend.handleCredentialSpecCreate(ctx, specReq, specFieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	if resp.StatusCode != http.StatusCreated {
		t.Logf("Spec creation failed - status: %d, err: %v, data: %+v", resp.StatusCode, resp.Err, resp.Data)
	}
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Equal(t, "test-spec", resp.Data["name"])
	assert.Equal(t, "vault_token", resp.Data["type"])
	assert.Equal(t, int64(3600), resp.Data["min_ttl"])
	assert.Equal(t, int64(86400), resp.Data["max_ttl"])
}

func TestSystemBackend_HandleCredentialSpecCreate_InvalidTTL(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)

	// First create a source
	// Create hvault source (required for vault_token type)
	createHVaultSource(t, backend, ctx, "test-source")

	// Create spec with invalid TTL (min > max)
	specSchema := backend.pathCredentials()[2].Fields
	specRaw := map[string]interface{}{
		"name":    "test-spec",
		"type":    "vault_token",
		"source":  "test-source",
		"min_ttl": 86400, // Greater than max_ttl
		"max_ttl": 3600,
		"config": map[string]interface{}{
			"mint_method": "vault_token",
			"token_role":  "test-role",
		},
	}

	specReq := createTestRequest(logical.CreateOperation, "cred/specs/test-spec", specRaw)
	specFieldData := createFieldData(specSchema, specRaw)

	resp, err := backend.handleCredentialSpecCreate(ctx, specReq, specFieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestSystemBackend_HandleCredentialSpecRead(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)

	// Create hvault source (required for vault_token type)
	createHVaultSource(t, backend, ctx, "test-source")

	specSchema := backend.pathCredentials()[2].Fields
	specRaw := map[string]interface{}{
		"name":   "test-spec",
		"type":   "vault_token",
		"source": "test-source",
		"config": map[string]interface{}{
			"mint_method": "vault_token",
			"token_role":  "test-role",
		},
	}
	specReq := createTestRequest(logical.CreateOperation, "cred/specs/test-spec", specRaw)
	specFieldData := createFieldData(specSchema, specRaw)
	createResp, err := backend.handleCredentialSpecCreate(ctx, specReq, specFieldData)
	require.NoError(t, err)
	require.NotNil(t, createResp)
	if createResp.Err != nil {
		t.Fatalf("Spec creation failed: %v", createResp.Err)
	}
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("Spec creation returned status %d (expected 201)", createResp.StatusCode)
	}

	// Read spec
	resp, err := backend.handleCredentialSpecRead(ctx, specReq, specFieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Logf("Spec read failed - status: %d, err: %v, data: %+v", resp.StatusCode, resp.Err, resp.Data)
	}
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "test-spec", resp.Data["name"])
}

func TestSystemBackend_HandleCredentialSpecUpdate(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)

	// Create hvault source (required for vault_token type)
	createHVaultSource(t, backend, ctx, "test-source")

	specSchema := backend.pathCredentials()[2].Fields
	specRaw := map[string]interface{}{
		"name":    "test-spec",
		"type":    "vault_token",
		"source":  "test-source",
		"min_ttl": 3600,
		"max_ttl": 86400,
		"config": map[string]interface{}{
			"mint_method": "vault_token",
			"token_role":  "test-role",
		},
	}
	specReq := createTestRequest(logical.CreateOperation, "cred/specs/test-spec", specRaw)
	specFieldData := createFieldData(specSchema, specRaw)
	_, err := backend.handleCredentialSpecCreate(ctx, specReq, specFieldData)
	require.NoError(t, err)

	// Update spec
	updateRaw := map[string]interface{}{
		"name":    "test-spec",
		"min_ttl": 7200,
		"max_ttl": 172800,
	}
	updateFieldData := createFieldData(specSchema, updateRaw)

	resp, err := backend.handleCredentialSpecUpdate(ctx, specReq, updateFieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Data["message"], "Successfully updated")
}

func TestSystemBackend_HandleCredentialSpecDelete(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)

	// Create source and spec
	sourceSchema := backend.pathCredentials()[0].Fields
	sourceRaw := map[string]interface{}{
		"name": "test-source",
		"type": "local",
	}
	sourceReq := createTestRequest(logical.CreateOperation, "cred/sources/test-source", sourceRaw)
	sourceFieldData := createFieldData(sourceSchema, sourceRaw)
	_, err := backend.handleCredentialSourceCreate(ctx, sourceReq, sourceFieldData)
	require.NoError(t, err)

	specSchema := backend.pathCredentials()[2].Fields
	specRaw := map[string]interface{}{
		"name":   "test-spec",
		"type":   "vault_token",
		"source": "test-source",
		"config": map[string]interface{}{
			"mint_method": "vault_token",
			"token_role":  "test-role",
		},
	}
	specReq := createTestRequest(logical.CreateOperation, "cred/specs/test-spec", specRaw)
	specFieldData := createFieldData(specSchema, specRaw)
	_, err = backend.handleCredentialSpecCreate(ctx, specReq, specFieldData)
	require.NoError(t, err)

	// Delete spec
	resp, err := backend.handleCredentialSpecDelete(ctx, specReq, specFieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Data["message"], "Successfully deleted")
}

func TestSystemBackend_HandleCredentialSpecList(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)

	// Create hvault source (required for vault_token type)
	createHVaultSource(t, backend, ctx, "test-source")

	// Create multiple specs
	specSchema := backend.pathCredentials()[2].Fields
	for _, name := range []string{"spec1", "spec2", "spec3"} {
		specRaw := map[string]interface{}{
			"name":   name,
			"type":   "vault_token",
			"source": "test-source",
			"config": map[string]interface{}{
				"mint_method": "vault_token",
				"token_role":  "test-role",
			},
		}
		specReq := createTestRequest(logical.CreateOperation, "cred/specs/"+name, specRaw)
		specFieldData := createFieldData(specSchema, specRaw)
		_, err := backend.handleCredentialSpecCreate(ctx, specReq, specFieldData)
		require.NoError(t, err)
	}

	// List specs
	listSchema := backend.pathCredentials()[3].Fields
	listRaw := map[string]interface{}{}
	listReq := createTestRequest(logical.ListOperation, "cred/specs/", listRaw)
	listFieldData := createFieldData(listSchema, listRaw)

	resp, err := backend.handleCredentialSpecList(ctx, listReq, listFieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	specs, ok := resp.Data["specs"].([]map[string]any)
	require.True(t, ok)
	assert.Len(t, specs, 3)
}
