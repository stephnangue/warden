package core

import (
	"net/http"
	"testing"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSystemBackend_PathPolicies(t *testing.T) {
	backend, _, _ := setupTestSystemBackend(t)

	paths := backend.pathPolicies()
	// One CRUD path and one list path per policy type.
	require.Len(t, paths, 4)

	// Check policies/cbp/{name} path
	assert.Equal(t, "policies/cbp/"+framework.GenericNameRegex("name"), paths[0].Pattern)
	assert.Contains(t, paths[0].Fields, "name")
	assert.Contains(t, paths[0].Fields, "policy")
	assert.Contains(t, paths[0].Fields, "cas")

	// Check policies/cbp/ list path
	assert.Equal(t, "policies/cbp/?$", paths[1].Pattern)
	assert.Contains(t, paths[1].Fields, "prefix")

	// Check policies/mcp/{name} path
	assert.Equal(t, "policies/mcp/"+framework.GenericNameRegex("name"), paths[2].Pattern)
	assert.Contains(t, paths[2].Fields, "name")
	assert.Contains(t, paths[2].Fields, "policy")
	assert.Contains(t, paths[2].Fields, "cas")

	// Check policies/mcp/ list path
	assert.Equal(t, "policies/mcp/?$", paths[3].Pattern)
	assert.Contains(t, paths[3].Fields, "prefix")
}

func TestSystemBackend_HandlePolicyCreate(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)

	schema := backend.pathPolicies()[0].Fields
	raw := map[string]interface{}{
		"name": "test-policy",
		"policy": `
path "secret/*" {
  capabilities = ["read", "list"]
}
`,
	}

	req := createTestRequest(logical.CreateOperation, "policies/cbp/test-policy", raw)
	fieldData := createFieldData(schema, raw)

	resp, err := backend.handlePolicyCreate(PolicyTypeCBP)(ctx, req, fieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Equal(t, "test-policy", resp.Data["name"])
}

// TestSystemBackend_HandleMCPPolicyRoundTrip drives an MCP document through the
// real handlers rather than calling ParseMCPPolicy directly, so the type
// actually reaches the parser and the store. Without this, deleting the MCP arm
// of parsePolicyForType would fall through to the CBP parser unnoticed.
func TestSystemBackend_HandleMCPPolicyRoundTrip(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)

	// paths[2] is the MCP CRUD path; see TestSystemBackend_PathPolicies.
	schema := backend.pathPolicies()[2].Fields
	document := `
path "mcp/gateway/*" {
  methods { allowed = ["tools/list"] }
  tools   { allowed = ["get_repository"] }
}
`
	raw := map[string]interface{}{"name": "gw-tools", "policy": document}

	req := createTestRequest(logical.CreateOperation, "policies/mcp/gw-tools", raw)
	resp, err := backend.handlePolicyCreate(PolicyTypeMCP)(ctx, req, createFieldData(schema, raw))
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	// It must land in the MCP view, parsed by the MCP parser.
	stored, err := backend.core.policyStore.GetPolicy(ctx, "gw-tools", PolicyTypeMCP)
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.Equal(t, PolicyTypeMCP, stored.Type)
	require.Len(t, stored.Paths, 1)
	require.Len(t, stored.Paths[0].Permissions.MCP, 1)
	assert.Equal(t, []string{"get_repository"}, stored.Paths[0].Permissions.MCP[0].AllowedTools)

	readReq := createTestRequest(logical.ReadOperation, "policies/mcp/gw-tools", raw)
	readResp, err := backend.handlePolicyRead(PolicyTypeMCP)(ctx, readReq, createFieldData(schema, raw))
	require.NoError(t, err)
	require.NotNil(t, readResp)
	assert.Equal(t, document, readResp.Data["policy"])
}

// TestSystemBackend_HandleMCPPolicyRejectsCBPGrammar proves the MCP endpoint is
// really parsed as MCP: a capabilities stanza is a valid CBP policy and must
// still be refused here.
func TestSystemBackend_HandleMCPPolicyRejectsCBPGrammar(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)

	schema := backend.pathPolicies()[2].Fields
	raw := map[string]interface{}{
		"name":   "wrong-grammar",
		"policy": "path \"mcp/gateway/*\" {\n  capabilities = [\"update\"]\n}\n",
	}

	req := createTestRequest(logical.CreateOperation, "policies/mcp/wrong-grammar", raw)
	resp, err := backend.handlePolicyCreate(PolicyTypeMCP)(ctx, req, createFieldData(schema, raw))
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.Err, "a CBP document must not be accepted on the MCP endpoint")
}

// TestSystemBackend_HandleMCPPolicyNameConflict exercises the cross-type
// uniqueness guard through the wire mapping, so the operator-facing status is
// pinned alongside the store-level behavior.
func TestSystemBackend_HandleMCPPolicyNameConflict(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)

	cbpSchema := backend.pathPolicies()[0].Fields
	cbpRaw := map[string]interface{}{
		"name":   "shared",
		"policy": "path \"mcp/gateway/*\" {\n  capabilities = [\"update\"]\n}\n",
	}
	resp, err := backend.handlePolicyCreate(PolicyTypeCBP)(ctx,
		createTestRequest(logical.CreateOperation, "policies/cbp/shared", cbpRaw),
		createFieldData(cbpSchema, cbpRaw))
	require.NoError(t, err)
	require.Nil(t, resp.Err)

	mcpSchema := backend.pathPolicies()[2].Fields
	mcpRaw := map[string]interface{}{
		"name":   "shared",
		"policy": "path \"mcp/gateway/*\" {\n  methods { allowed = [\"tools/list\"] }\n}\n",
	}
	conflict, err := backend.handlePolicyCreate(PolicyTypeMCP)(ctx,
		createTestRequest(logical.CreateOperation, "policies/mcp/shared", mcpRaw),
		createFieldData(mcpSchema, mcpRaw))
	require.NoError(t, err)
	require.NotNil(t, conflict.Err)
	assert.Contains(t, conflict.Err.Error(), "already in use by a cbp policy")
}

func TestSystemBackend_HandlePolicyCreate_InvalidPolicy(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)

	schema := backend.pathPolicies()[0].Fields
	raw := map[string]interface{}{
		"name":   "test-policy",
		"policy": "this is not valid HCL {{{",
	}

	req := createTestRequest(logical.CreateOperation, "policies/cbp/test-policy", raw)
	fieldData := createFieldData(schema, raw)

	resp, err := backend.handlePolicyCreate(PolicyTypeCBP)(ctx, req, fieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotNil(t, resp.Err)
}

func TestSystemBackend_HandlePolicyRead(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)

	// First create a policy
	schema := backend.pathPolicies()[0].Fields
	raw := map[string]interface{}{
		"name": "test-policy",
		"policy": `
path "secret/*" {
  capabilities = ["read"]
}
`,
	}

	req := createTestRequest(logical.CreateOperation, "policies/cbp/test-policy", raw)
	fieldData := createFieldData(schema, raw)

	_, err := backend.handlePolicyCreate(PolicyTypeCBP)(ctx, req, fieldData)
	require.NoError(t, err)

	// Now read it
	resp, err := backend.handlePolicyRead(PolicyTypeCBP)(ctx, req, fieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "test-policy", resp.Data["name"])
	assert.Contains(t, resp.Data["policy"], "secret/*")
}

func TestSystemBackend_HandlePolicyRead_NotFound(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)

	schema := backend.pathPolicies()[0].Fields
	raw := map[string]interface{}{
		"name": "nonexistent",
	}

	req := createTestRequest(logical.ReadOperation, "policies/cbp/nonexistent", raw)
	fieldData := createFieldData(schema, raw)

	resp, err := backend.handlePolicyRead(PolicyTypeCBP)(ctx, req, fieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestSystemBackend_HandlePolicyUpdate(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)

	// First create a policy
	schema := backend.pathPolicies()[0].Fields
	createRaw := map[string]interface{}{
		"name": "test-policy",
		"policy": `
path "secret/*" {
  capabilities = ["read"]
}
`,
	}

	req := createTestRequest(logical.CreateOperation, "policies/cbp/test-policy", createRaw)
	fieldData := createFieldData(schema, createRaw)

	_, err := backend.handlePolicyCreate(PolicyTypeCBP)(ctx, req, fieldData)
	require.NoError(t, err)

	// Now update it
	updateRaw := map[string]interface{}{
		"name": "test-policy",
		"policy": `
path "secret/*" {
  capabilities = ["read", "list", "create"]
}
`,
	}
	fieldData = createFieldData(schema, updateRaw)

	resp, err := backend.handlePolicyUpdate(PolicyTypeCBP)(ctx, req, fieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Data["message"], "Successfully updated")
}

func TestSystemBackend_HandlePolicyDelete(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)

	// First create a policy
	schema := backend.pathPolicies()[0].Fields
	raw := map[string]interface{}{
		"name": "test-policy",
		"policy": `
path "secret/*" {
  capabilities = ["read"]
}
`,
	}

	req := createTestRequest(logical.CreateOperation, "policies/cbp/test-policy", raw)
	fieldData := createFieldData(schema, raw)

	_, err := backend.handlePolicyCreate(PolicyTypeCBP)(ctx, req, fieldData)
	require.NoError(t, err)

	// Now delete it
	resp, err := backend.handlePolicyDelete(PolicyTypeCBP)(ctx, req, fieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Data["message"], "Successfully deleted")
}

func TestSystemBackend_HandlePolicyList(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)

	// Create some policies
	schema := backend.pathPolicies()[0].Fields
	for _, name := range []string{"policy1", "policy2", "policy3"} {
		raw := map[string]interface{}{
			"name": name,
			"policy": `
path "secret/*" {
  capabilities = ["read"]
}
`,
		}
		fieldData := createFieldData(schema, raw)
		req := createTestRequest(logical.CreateOperation, "policies/cbp/"+name, raw)
		_, err := backend.handlePolicyCreate(PolicyTypeCBP)(ctx, req, fieldData)
		require.NoError(t, err)
	}

	// List policies
	listSchema := backend.pathPolicies()[1].Fields
	listRaw := map[string]interface{}{}
	req := createTestRequest(logical.ListOperation, "policies/cbp/", listRaw)
	fieldData := createFieldData(listSchema, listRaw)

	resp, err := backend.handlePolicyList(PolicyTypeCBP)(ctx, req, fieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	keys, ok := resp.Data["keys"].([]string)
	require.True(t, ok)
	assert.Len(t, keys, 3)
}

func TestSystemBackend_HandlePolicyList_WithPrefix(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)

	// Create policies with different prefixes
	schema := backend.pathPolicies()[0].Fields
	for _, name := range []string{"app-policy1", "app-policy2", "other-policy"} {
		raw := map[string]interface{}{
			"name": name,
			"policy": `
path "secret/*" {
  capabilities = ["read"]
}
`,
		}
		fieldData := createFieldData(schema, raw)
		req := createTestRequest(logical.CreateOperation, "policies/cbp/"+name, raw)
		_, err := backend.handlePolicyCreate(PolicyTypeCBP)(ctx, req, fieldData)
		require.NoError(t, err)
	}

	// List policies with prefix
	listSchema := backend.pathPolicies()[1].Fields
	listRaw := map[string]interface{}{
		"prefix": "app-",
	}
	req := createTestRequest(logical.ListOperation, "policies/cbp/", listRaw)
	fieldData := createFieldData(listSchema, listRaw)

	resp, err := backend.handlePolicyList(PolicyTypeCBP)(ctx, req, fieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	keys, ok := resp.Data["keys"].([]string)
	require.True(t, ok)
	assert.Len(t, keys, 2)
}

// Helper Response Tests

func TestSystemBackend_RespondSuccess(t *testing.T) {
	backend, _, _ := setupTestSystemBackend(t)

	resp := backend.respondSuccess(map[string]any{"key": "value"})
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "value", resp.Data["key"])
}

func TestSystemBackend_RespondCreated(t *testing.T) {
	backend, _, _ := setupTestSystemBackend(t)

	resp := backend.respondCreated(map[string]any{"key": "value"})
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Equal(t, "value", resp.Data["key"])
}

func TestLogical_ErrorResponse(t *testing.T) {
	testCases := []struct {
		name           string
		err            error
		expectedStatus int
	}{
		{
			name:           "bad request",
			err:            logical.ErrBadRequest("invalid input"),
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "not found",
			err:            logical.ErrNotFound("resource not found"),
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "conflict",
			err:            logical.ErrConflict("already exists"),
			expectedStatus: http.StatusConflict,
		},
		{
			name:           "forbidden",
			err:            logical.ErrForbidden("access denied"),
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "internal error",
			err:            logical.ErrInternal("something went wrong"),
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:           "service unavailable",
			err:            logical.ErrServiceUnavailable("service down"),
			expectedStatus: http.StatusServiceUnavailable,
		},
		{
			name:           "plain error defaults to 500",
			err:            newTestError("plain error"),
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp := logical.ErrorResponse(tc.err)
			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestValidateMountPath(t *testing.T) {
	testCases := []struct {
		path    string
		wantErr bool
	}{
		{"valid-path", false},
		{"valid/nested/path", false},
		{"sys/invalid", true},   // Reserved prefix
		{"auth/invalid", true},  // Reserved prefix
		{"audit/invalid", true}, // Reserved prefix
		{"-invalid", true},      // Starts with hyphen
		{"_invalid", true},      // Starts with underscore
		{"valid-path/", false},  // Trailing slash is OK

		// Transparent mode reserved words
		{"role", true},            // Reserved segment
		{"role/admin", true},      // Path containing reserved segment
		{"my/role/path", true},    // Reserved segment in middle
		{"gateway", true},         // Reserved segment
		{"gateway/api", true},     // Path containing reserved segment
		{"my/gateway/path", true}, // Reserved segment in middle

		// Similar names that should be allowed
		{"myrole", false},          // Not a segment match
		{"rolename", false},        // Not a segment match
		{"mygateway", false},       // Not a segment match
		{"gatewayname", false},     // Not a segment match
		{"my-role-path", false},    // Hyphen prevents segment match
		{"my-gateway-path", false}, // Hyphen prevents segment match
	}

	for _, tc := range testCases {
		t.Run(tc.path, func(t *testing.T) {
			err := ValidateMountPath(tc.path)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestConvertMetadataToStringMap(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		result := convertMetadataToStringMap(nil)
		assert.Nil(t, result)
	})

	t.Run("string values", func(t *testing.T) {
		input := map[string]any{
			"key1": "value1",
			"key2": "value2",
		}
		result := convertMetadataToStringMap(input)
		assert.Equal(t, "value1", result["key1"])
		assert.Equal(t, "value2", result["key2"])
	})

	t.Run("non-string values", func(t *testing.T) {
		input := map[string]any{
			"int":   123,
			"bool":  true,
			"float": 1.5,
		}
		result := convertMetadataToStringMap(input)
		assert.Equal(t, "123", result["int"])
		assert.Equal(t, "true", result["bool"])
		assert.Equal(t, "1.5", result["float"])
	})
}

func TestConvertToStringMap(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		result := convertToStringMap(nil)
		assert.Nil(t, result)
	})

	t.Run("mixed values", func(t *testing.T) {
		input := map[string]any{
			"string": "value",
			"int":    42,
		}
		result := convertToStringMap(input)
		assert.Equal(t, "value", result["string"])
		assert.Equal(t, "42", result["int"])
	})
}
