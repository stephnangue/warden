package core

import (
	"net/http"
	"testing"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/stephnangue/warden/audit"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSystemBackend_PathAudit(t *testing.T) {
	backend, _, _ := setupTestSystemBackend(t)

	paths := backend.pathAudit()
	require.Len(t, paths, 2)

	// Check audit/{path} path
	assert.Equal(t, "audit/"+framework.MatchAllRegex("path"), paths[0].Pattern)
	assert.Contains(t, paths[0].Fields, "path")
	assert.Contains(t, paths[0].Fields, "type")
	assert.Contains(t, paths[0].Fields, "description")
	assert.Contains(t, paths[0].Fields, "config")

	// Check audit/ list path
	assert.Equal(t, "audit/?$", paths[1].Pattern)
}

func TestSystemBackend_PathAuditHash(t *testing.T) {
	backend, _, _ := setupTestSystemBackend(t)

	paths := backend.pathAuditHash()
	require.Len(t, paths, 1)

	// Check audit-hash/{path} path
	assert.Equal(t, "audit-hash/"+framework.MatchAllRegex("path"), paths[0].Pattern)
	assert.Contains(t, paths[0].Fields, "path")
	assert.Contains(t, paths[0].Fields, "input")
}

func TestSystemBackend_HandleAuditCreate(t *testing.T) {
	backend, ctx, core := setupTestSystemBackend(t)

	// Register mock audit factory and initialize audit components
	core.auditDevices = make(map[string]audit.Factory)
	core.auditDevices["mock"] = &mockAuditFactory{}
	core.audit = NewMountTable()
	core.auditManager = newMockAuditManagerFull()

	schema := backend.pathAudit()[0].Fields
	raw := map[string]interface{}{
		"path":        "test-audit",
		"type":        "mock",
		"description": "Test audit device",
		"config":      map[string]interface{}{"skip_test": "true"},
	}

	req := createTestRequest(logical.CreateOperation, "audit/test-audit", raw)
	fieldData := createFieldData(schema, raw)

	resp, err := backend.handleAuditCreate(ctx, req, fieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Contains(t, resp.Data, "accessor")
	assert.Equal(t, "test-audit/", resp.Data["path"])
}

func TestSystemBackend_HandleAuditCreate_GeneratesHMACKey(t *testing.T) {
	backend, ctx, core := setupTestSystemBackend(t)

	core.auditDevices = make(map[string]audit.Factory)
	core.auditDevices["mock"] = &mockAuditFactory{}
	core.audit = NewMountTable()
	core.auditManager = newMockAuditManagerFull()

	schema := backend.pathAudit()[0].Fields
	raw := map[string]interface{}{
		"path":   "test-audit",
		"type":   "mock",
		"config": map[string]interface{}{"skip_test": "true"}, // No hmac_key provided
	}

	req := createTestRequest(logical.CreateOperation, "audit/test-audit", raw)
	fieldData := createFieldData(schema, raw)

	resp, err := backend.handleAuditCreate(ctx, req, fieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	// Verify HMAC key was generated in the audit entry
	require.Len(t, core.audit.Entries, 1)
	hmacKey, ok := core.audit.Entries[0].Config["hmac_key"].(string)
	assert.True(t, ok)
	assert.NotEmpty(t, hmacKey)
	assert.Len(t, hmacKey, 64) // 32 bytes hex-encoded = 64 chars
}

func TestSystemBackend_HandleAuditCreate_UnsupportedType(t *testing.T) {
	backend, ctx, core := setupTestSystemBackend(t)

	core.auditDevices = make(map[string]audit.Factory)
	core.audit = NewMountTable()
	core.auditManager = newMockAuditManagerFull()

	schema := backend.pathAudit()[0].Fields
	raw := map[string]interface{}{
		"path":   "test-audit",
		"type":   "unsupported",
		"config": map[string]interface{}{"skip_test": "true"},
	}

	req := createTestRequest(logical.CreateOperation, "audit/test-audit", raw)
	fieldData := createFieldData(schema, raw)

	resp, err := backend.handleAuditCreate(ctx, req, fieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotEqual(t, http.StatusCreated, resp.StatusCode)
}

func TestSystemBackend_HandleAuditRead(t *testing.T) {
	backend, ctx, core := setupTestSystemBackend(t)

	// Initialize audit components
	core.auditDevices = make(map[string]audit.Factory)
	core.auditDevices["mock"] = &mockAuditFactory{}
	core.audit = NewMountTable()
	core.auditManager = newMockAuditManagerFull()

	// First create an audit device
	entry := &MountEntry{
		Class:       mountClassAudit,
		Type:        "mock",
		Path:        "test-audit/",
		Description: "Test audit",
		Config:      map[string]any{"skip_test": "true", "hmac_key": "test-hmac-key"},
	}
	err := core.EnableAudit(ctx, entry, false)
	require.NoError(t, err)

	// Now read it
	schema := backend.pathAudit()[0].Fields
	raw := map[string]interface{}{
		"path": "test-audit",
	}

	req := createTestRequest(logical.ReadOperation, "audit/test-audit", raw)
	fieldData := createFieldData(schema, raw)

	resp, err := backend.handleAuditRead(ctx, req, fieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "mock", resp.Data["type"])
	assert.Equal(t, "test-audit/", resp.Data["path"])

	// Verify HMAC key is masked
	config, ok := resp.Data["config"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, maskMountConfigValue, config["hmac_key"])
}

func TestSystemBackend_HandleAuditRead_NotFound(t *testing.T) {
	backend, ctx, core := setupTestSystemBackend(t)

	core.audit = NewMountTable()

	schema := backend.pathAudit()[0].Fields
	raw := map[string]interface{}{
		"path": "nonexistent",
	}

	req := createTestRequest(logical.ReadOperation, "audit/nonexistent", raw)
	fieldData := createFieldData(schema, raw)

	resp, err := backend.handleAuditRead(ctx, req, fieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestSystemBackend_HandleAuditDelete(t *testing.T) {
	backend, ctx, core := setupTestSystemBackend(t)

	// Initialize audit components
	core.auditDevices = make(map[string]audit.Factory)
	core.auditDevices["mock"] = &mockAuditFactory{}
	core.audit = NewMountTable()
	core.auditManager = newMockAuditManagerFull()

	// Create two audit devices (need at least 2 to delete one)
	entry1 := &MountEntry{
		Class:       mountClassAudit,
		Type:        "mock",
		Path:        "audit1/",
		Description: "Test audit 1",
		Config:      map[string]any{"skip_test": "true"},
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	entry2 := &MountEntry{
		Class:       mountClassAudit,
		Type:        "mock",
		Path:        "audit2/",
		Description: "Test audit 2",
		Config:      map[string]any{"skip_test": "true"},
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	require.NoError(t, core.EnableAudit(ctx, entry1, false))
	require.NoError(t, core.EnableAudit(ctx, entry2, false))

	// Now delete one
	schema := backend.pathAudit()[0].Fields
	raw := map[string]interface{}{
		"path": "audit1",
	}

	req := createTestRequest(logical.DeleteOperation, "audit/audit1", raw)
	fieldData := createFieldData(schema, raw)

	resp, err := backend.handleAuditDelete(ctx, req, fieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Data["message"], "Successfully disabled")
}

func TestSystemBackend_HandleAuditDelete_BlocksLastDevice(t *testing.T) {
	backend, ctx, core := setupTestSystemBackend(t)

	// Initialize audit components
	core.auditDevices = make(map[string]audit.Factory)
	core.auditDevices["mock"] = &mockAuditFactory{}
	core.audit = NewMountTable()
	core.auditManager = newMockAuditManagerFull()

	// Create only one audit device
	entry := &MountEntry{
		Class:       mountClassAudit,
		Type:        "mock",
		Path:        "only-audit/",
		Description: "Only audit device",
		Config:      map[string]any{"skip_test": "true"},
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	require.NoError(t, core.EnableAudit(ctx, entry, false))

	// Try to delete it - should fail
	schema := backend.pathAudit()[0].Fields
	raw := map[string]interface{}{
		"path": "only-audit",
	}

	req := createTestRequest(logical.DeleteOperation, "audit/only-audit", raw)
	fieldData := createFieldData(schema, raw)

	resp, err := backend.handleAuditDelete(ctx, req, fieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.NotNil(t, resp.Err)
	assert.Contains(t, resp.Err.Error(), "cannot disable the last audit device")
	assert.Contains(t, resp.Err.Error(), "fail-closed")

	// Verify the device is still there
	assert.Len(t, core.audit.Entries, 1)
}

func TestSystemBackend_HandleAuditDelete_AllowsWithMultipleDevices(t *testing.T) {
	backend, ctx, core := setupTestSystemBackend(t)

	// Initialize audit components
	core.auditDevices = make(map[string]audit.Factory)
	core.auditDevices["mock"] = &mockAuditFactory{}
	core.audit = NewMountTable()
	core.auditManager = newMockAuditManagerFull()

	// Create three audit devices
	for i := 1; i <= 3; i++ {
		entry := &MountEntry{
			Class:       mountClassAudit,
			Type:        "mock",
			Path:        "audit" + string(rune('0'+i)) + "/",
			Description: "Test audit",
			Config:      map[string]any{"skip_test": "true"},
			NamespaceID: namespace.RootNamespaceID,
			namespace:   namespace.RootNamespace,
		}
		require.NoError(t, core.EnableAudit(ctx, entry, false))
	}
	require.Len(t, core.audit.Entries, 3)

	// Delete first device - should succeed
	schema := backend.pathAudit()[0].Fields
	raw := map[string]interface{}{
		"path": "audit1",
	}

	req := createTestRequest(logical.DeleteOperation, "audit/audit1", raw)
	fieldData := createFieldData(schema, raw)

	resp, err := backend.handleAuditDelete(ctx, req, fieldData)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Len(t, core.audit.Entries, 2)

	// Delete second device - should succeed
	raw["path"] = "audit2"
	fieldData = createFieldData(schema, raw)
	req = createTestRequest(logical.DeleteOperation, "audit/audit2", raw)

	resp, err = backend.handleAuditDelete(ctx, req, fieldData)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Len(t, core.audit.Entries, 1)

	// Try to delete last device - should fail
	raw["path"] = "audit3"
	fieldData = createFieldData(schema, raw)
	req = createTestRequest(logical.DeleteOperation, "audit/audit3", raw)

	resp, err = backend.handleAuditDelete(ctx, req, fieldData)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.NotNil(t, resp.Err)
	assert.Contains(t, resp.Err.Error(), "cannot disable the last audit device")
}

func TestSystemBackend_HandleAuditList(t *testing.T) {
	backend, ctx, core := setupTestSystemBackend(t)

	// Initialize audit components
	core.auditDevices = make(map[string]audit.Factory)
	core.auditDevices["mock"] = &mockAuditFactory{}
	core.audit = NewMountTable()
	core.auditManager = newMockAuditManagerFull()

	// Create audit devices
	entry1 := &MountEntry{
		Class:       mountClassAudit,
		Type:        "mock",
		Path:        "audit1/",
		Description: "Audit 1",
		Config:      map[string]any{"skip_test": "true", "hmac_key": "secret-key-1"},
	}
	entry2 := &MountEntry{
		Class:       mountClassAudit,
		Type:        "mock",
		Path:        "audit2/",
		Description: "Audit 2",
		Config:      map[string]any{"skip_test": "true", "hmac_key": "secret-key-2"},
	}
	require.NoError(t, core.EnableAudit(ctx, entry1, false))
	require.NoError(t, core.EnableAudit(ctx, entry2, false))

	// List audit devices
	schema := backend.pathAudit()[1].Fields
	raw := map[string]interface{}{}

	req := createTestRequest(logical.ListOperation, "audit/", raw)
	fieldData := createFieldData(schema, raw)

	resp, err := backend.handleAuditList(ctx, req, fieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify both devices are listed
	assert.Contains(t, resp.Data, "audit1/")
	assert.Contains(t, resp.Data, "audit2/")

	// Verify HMAC keys are masked in the list
	audit1Data, ok := resp.Data["audit1/"].(map[string]any)
	require.True(t, ok)
	audit1Config, ok := audit1Data["config"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, maskMountConfigValue, audit1Config["hmac_key"])
}

func TestSystemBackend_HandleAuditHash(t *testing.T) {
	backend, ctx, core := setupTestSystemBackend(t)

	// Initialize audit components
	core.auditDevices = make(map[string]audit.Factory)
	core.auditDevices["mock"] = &mockAuditFactory{}
	core.audit = NewMountTable()
	core.auditManager = newMockAuditManagerFull()

	// Create an audit device with a known HMAC key
	entry := &MountEntry{
		Class:       mountClassAudit,
		Type:        "mock",
		Path:        "test-audit/",
		Description: "Test audit",
		Config:      map[string]any{"skip_test": "true", "hmac_key": "test-hmac-key-12345"},
	}
	require.NoError(t, core.EnableAudit(ctx, entry, false))

	// Call audit-hash endpoint
	schema := backend.pathAuditHash()[0].Fields
	raw := map[string]interface{}{
		"path":  "test-audit",
		"input": "sensitive-value",
	}

	req := createTestRequest(logical.CreateOperation, "audit-hash/test-audit", raw)
	fieldData := createFieldData(schema, raw)

	resp, err := backend.handleAuditHash(ctx, req, fieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Data, "hash")

	hash, ok := resp.Data["hash"].(string)
	require.True(t, ok)
	assert.NotEmpty(t, hash)
	assert.True(t, len(hash) > 20) // HMAC hash should be reasonably long
}

func TestSystemBackend_HandleAuditHash_NotFound(t *testing.T) {
	backend, ctx, core := setupTestSystemBackend(t)

	core.audit = NewMountTable()

	schema := backend.pathAuditHash()[0].Fields
	raw := map[string]interface{}{
		"path":  "nonexistent",
		"input": "value",
	}

	req := createTestRequest(logical.CreateOperation, "audit-hash/nonexistent", raw)
	fieldData := createFieldData(schema, raw)

	resp, err := backend.handleAuditHash(ctx, req, fieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestSystemBackend_HandleAuditHash_EmptyInput(t *testing.T) {
	backend, ctx, core := setupTestSystemBackend(t)

	// Initialize audit components
	core.auditDevices = make(map[string]audit.Factory)
	core.auditDevices["mock"] = &mockAuditFactory{}
	core.audit = NewMountTable()
	core.auditManager = newMockAuditManagerFull()

	// Create an audit device
	entry := &MountEntry{
		Class:       mountClassAudit,
		Type:        "mock",
		Path:        "test-audit/",
		Description: "Test audit",
		Config:      map[string]any{"skip_test": "true", "hmac_key": "test-key"},
	}
	require.NoError(t, core.EnableAudit(ctx, entry, false))

	// Call with empty input
	schema := backend.pathAuditHash()[0].Fields
	raw := map[string]interface{}{
		"path":  "test-audit",
		"input": "",
	}

	req := createTestRequest(logical.CreateOperation, "audit-hash/test-audit", raw)
	fieldData := createFieldData(schema, raw)

	resp, err := backend.handleAuditHash(ctx, req, fieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.NotNil(t, resp.Err)
	assert.Contains(t, resp.Err.Error(), "input is required")
}

func TestSystemBackend_HandleAuditHash_ConsistentResults(t *testing.T) {
	backend, ctx, core := setupTestSystemBackend(t)

	// Initialize audit components
	core.auditDevices = make(map[string]audit.Factory)
	core.auditDevices["mock"] = &mockAuditFactory{}
	core.audit = NewMountTable()
	core.auditManager = newMockAuditManagerFull()

	// Create an audit device
	entry := &MountEntry{
		Class:       mountClassAudit,
		Type:        "mock",
		Path:        "test-audit/",
		Description: "Test audit",
		Config:      map[string]any{"skip_test": "true", "hmac_key": "consistent-key"},
	}
	require.NoError(t, core.EnableAudit(ctx, entry, false))

	schema := backend.pathAuditHash()[0].Fields

	// Hash the same value twice
	raw := map[string]interface{}{
		"path":  "test-audit",
		"input": "same-value",
	}

	req1 := createTestRequest(logical.CreateOperation, "audit-hash/test-audit", raw)
	fieldData1 := createFieldData(schema, raw)
	resp1, err := backend.handleAuditHash(ctx, req1, fieldData1)
	require.NoError(t, err)

	req2 := createTestRequest(logical.CreateOperation, "audit-hash/test-audit", raw)
	fieldData2 := createFieldData(schema, raw)
	resp2, err := backend.handleAuditHash(ctx, req2, fieldData2)
	require.NoError(t, err)

	// Hashes should be identical for the same input
	assert.Equal(t, resp1.Data["hash"], resp2.Data["hash"])

	// Different input should produce different hash
	raw["input"] = "different-value"
	req3 := createTestRequest(logical.CreateOperation, "audit-hash/test-audit", raw)
	fieldData3 := createFieldData(schema, raw)
	resp3, err := backend.handleAuditHash(ctx, req3, fieldData3)
	require.NoError(t, err)

	assert.NotEqual(t, resp1.Data["hash"], resp3.Data["hash"])
}
