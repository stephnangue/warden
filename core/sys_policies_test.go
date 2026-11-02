package core

import (
	"go/ast"
	"go/parser"
	"go/token"
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
	// The three written, plus the seeded CBP built-ins.
	assert.ElementsMatch(t, []string{"default-cbp", "default-sponsor", "policy1", "policy2", "policy3"}, keys)
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

// TestSystemBackend_PolicyNamesMustBeCanonical: the policy endpoints act on the
// name exactly as the path spells it. A deny on sys/policies/cbp/admin is
// matched against the raw path, so if .../Admin were folded to "admin" by the
// handler it would reach the policy the deny protects.
func TestSystemBackend_PolicyNamesMustBeCanonical(t *testing.T) {
	c := createTestCore(t)
	ctx := rootCtx()
	const body = `path "secret/*" { capabilities = ["read"] }`

	// The CBP matches the path as written and does not fold it: this is what
	// the handlers must not undo.
	guard, err := NewCBP(ctx, []*Policy{testParsePolicy(t, `
path "sys/policies/cbp/*"     { capabilities = ["create", "read", "update", "delete"] }
path "sys/policies/cbp/admin" { capabilities = ["deny"] }
`)})
	require.NoError(t, err)
	te := &logical.TokenEntry{}
	assert.False(t, guard.AllowOperation(ctx, &logical.Request{Operation: logical.UpdateOperation, Path: "sys/policies/cbp/admin"}, te, false).Allowed)
	assert.True(t, guard.AllowOperation(ctx, &logical.Request{Operation: logical.UpdateOperation, Path: "sys/policies/cbp/Admin"}, te, false).Allowed)

	for _, typ := range []string{"cbp", "mcp"} {
		policy := body
		if typ == "mcp" {
			policy = `
path "mcp/gateway/*" {
  methods { allowed = ["tools/list"] }
}
`
		}
		resp, err := c.systemBackend.HandleRequest(ctx, &logical.Request{
			Operation: logical.CreateOperation, Path: "policies/" + typ + "/admin",
			Data: map[string]any{"policy": policy},
		})
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, resp.StatusCode, "%s: %v", typ, resp.Err)

		for _, op := range []logical.Operation{logical.CreateOperation, logical.ReadOperation, logical.UpdateOperation, logical.DeleteOperation} {
			resp, err := c.systemBackend.HandleRequest(ctx, &logical.Request{
				Operation: op, Path: "policies/" + typ + "/Admin",
				Data: map[string]any{"policy": policy},
			})
			require.NoError(t, err)
			require.NotNil(t, resp)
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "%s %s", typ, op)
			require.Error(t, resp.Err)
			assert.Contains(t, resp.Err.Error(), `policy name "Admin" is not canonical: use "admin"`, "%s %s", typ, op)
		}

		// The canonical spelling still works, and the policy was not touched.
		resp, err = c.systemBackend.HandleRequest(ctx, &logical.Request{Operation: logical.ReadOperation, Path: "policies/" + typ + "/admin"})
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, policy, resp.Data["policy"])
		assert.EqualValues(t, 1, resp.Data["data_version"])

		resp, err = c.systemBackend.HandleRequest(ctx, &logical.Request{Operation: logical.DeleteOperation, Path: "policies/" + typ + "/admin"})
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	}
}

// TestPolicyHandlers_ReadNameThroughPolicyPathName pins every policy handler to
// policyPathName, so none reads the path's name raw and hands it to the store,
// which would fold its case. It is a tripwire, not a proof: it catches the
// d.Get("name") a handler would naturally write, not every way to read the
// name (GetOk, Raw, req.Path). TestSystemBackend_PolicyNamesMustBeCanonical
// checks the behaviour itself.
func TestPolicyHandlers_ReadNameThroughPolicyPathName(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "sys_policies.go", nil, 0)
	require.NoError(t, err)

	handlers := map[string]bool{
		"handlePolicyCreate": false, "handlePolicyRead": false,
		"handlePolicyUpdate": false, "handlePolicyDelete": false,
	}
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if _, ok := handlers[fd.Name.Name]; !ok {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "policyPathName" {
				handlers[fd.Name.Name] = true
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Get" && len(call.Args) == 1 {
				if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Value == `"name"` {
					t.Errorf("%s reads the name field directly; use policyPathName", fd.Name.Name)
				}
			}
			return true
		})
	}
	for name, uses := range handlers {
		assert.True(t, uses, "%s must read the policy name through policyPathName", name)
	}
}
