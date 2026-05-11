package core

import (
	"context"
	"net/http"
	"testing"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validSkillFields returns a complete, schema-valid field map for creating
// a skill. Tests mutate the returned map to exercise edge cases.
func validSkillFields(name string) map[string]interface{} {
	return map[string]interface{}{
		"name":        name,
		"description": "a test skill",
		"category":    SkillCategoryCustom,
		"body":        "# heading\nbody text\n",
	}
}

// skillPathSchemas returns the field schemas for the CRUD and LIST paths,
// in that order.
func skillPathSchemas(b *SystemBackend) (crud, list map[string]*framework.FieldSchema) {
	paths := b.pathSkills()
	return paths[0].Fields, paths[1].Fields
}

func TestSystemBackend_PathSkills_Shape(t *testing.T) {
	backend, _, _ := setupTestSystemBackend(t)

	paths := backend.pathSkills()
	require.Len(t, paths, 2)
	assert.Equal(t, "skills/"+framework.GenericNameRegex("name"), paths[0].Pattern)
	assert.Equal(t, "skills/?$", paths[1].Pattern)

	// CRUD path must expose all four operations.
	for _, op := range []logical.Operation{
		logical.CreateOperation,
		logical.ReadOperation,
		logical.UpdateOperation,
		logical.DeleteOperation,
	} {
		_, ok := paths[0].Operations[op]
		assert.True(t, ok, "operation %s missing from CRUD path", op)
	}

	// LIST path exposes only the list operation.
	_, ok := paths[1].Operations[logical.ListOperation]
	assert.True(t, ok)
}

func TestSystemBackend_HandleSkillCreate_Success(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)
	schema, _ := skillPathSchemas(backend)
	raw := validSkillFields("runbook-1")
	req := createTestRequest(logical.CreateOperation, "skills/runbook-1", raw)
	fd := createFieldData(schema, raw)

	resp, err := backend.handleSkillCreate(ctx, req, fd)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Equal(t, "runbook-1", resp.Data["name"])
	assert.Equal(t, SkillOriginUser, resp.Data["origin"])
	// LIST short-form is the only place body is omitted; CREATE returns it.
	assert.Equal(t, "# heading\nbody text\n", resp.Data["body"])
}

func TestSystemBackend_HandleSkillCreate_Duplicate(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)
	schema, _ := skillPathSchemas(backend)
	raw := validSkillFields("dup")
	req := createTestRequest(logical.CreateOperation, "skills/dup", raw)
	fd := createFieldData(schema, raw)

	_, err := backend.handleSkillCreate(ctx, req, fd)
	require.NoError(t, err)

	resp, err := backend.handleSkillCreate(ctx, req, fd)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
}

func TestSystemBackend_HandleSkillCreate_ValidationRejected(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)
	schema, _ := skillPathSchemas(backend)

	cases := []struct {
		name   string
		mutate func(m map[string]interface{})
	}{
		{"bad name", func(m map[string]interface{}) { m["name"] = "Bad_Name" }},
		{"bad category", func(m map[string]interface{}) { m["category"] = "weird" }},
		{"empty body", func(m map[string]interface{}) { m["body"] = "" }},
		{"provider-guide without provider", func(m map[string]interface{}) {
			m["category"] = SkillCategoryProviderGuide
			delete(m, "provider")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := validSkillFields("ok-name")
			tc.mutate(raw)
			req := createTestRequest(logical.CreateOperation, "skills/x", raw)
			fd := createFieldData(schema, raw)

			resp, err := backend.handleSkillCreate(ctx, req, fd)
			require.NoError(t, err)
			require.NotNil(t, resp)
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "case %q", tc.name)
		})
	}
}

func TestSystemBackend_HandleSkillRead_Success(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)
	schema, _ := skillPathSchemas(backend)
	raw := validSkillFields("readable")
	req := createTestRequest(logical.CreateOperation, "skills/readable", raw)
	fd := createFieldData(schema, raw)
	_, err := backend.handleSkillCreate(ctx, req, fd)
	require.NoError(t, err)

	readReq := createTestRequest(logical.ReadOperation, "skills/readable", raw)
	resp, err := backend.handleSkillRead(ctx, readReq, fd)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "readable", resp.Data["name"])
	assert.Equal(t, "# heading\nbody text\n", resp.Data["body"])
}

func TestSystemBackend_HandleSkillRead_NotFound(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)
	schema, _ := skillPathSchemas(backend)
	raw := map[string]interface{}{"name": "ghost"}
	req := createTestRequest(logical.ReadOperation, "skills/ghost", raw)
	fd := createFieldData(schema, raw)

	resp, err := backend.handleSkillRead(ctx, req, fd)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestSystemBackend_HandleSkillUpdate_MergesAndBumpsVersion(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)
	schema, _ := skillPathSchemas(backend)

	createRaw := validSkillFields("evolves")
	createReq := createTestRequest(logical.CreateOperation, "skills/evolves", createRaw)
	createFD := createFieldData(schema, createRaw)
	_, err := backend.handleSkillCreate(ctx, createReq, createFD)
	require.NoError(t, err)

	updateRaw := map[string]interface{}{
		"name":        "evolves",
		"description": "patched description",
	}
	updateReq := createTestRequest(logical.UpdateOperation, "skills/evolves", updateRaw)
	updateFD := createFieldData(schema, updateRaw)

	resp, err := backend.handleSkillUpdate(ctx, updateReq, updateFD)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "patched description", resp.Data["description"])
	// Body unchanged because patch did not include it.
	assert.Equal(t, "# heading\nbody text\n", resp.Data["body"])
	assert.Equal(t, 2, resp.Data["version"])
}

func TestSystemBackend_HandleSkillUpdate_NotFound(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)
	schema, _ := skillPathSchemas(backend)
	raw := map[string]interface{}{
		"name":        "ghost",
		"description": "x",
	}
	req := createTestRequest(logical.UpdateOperation, "skills/ghost", raw)
	fd := createFieldData(schema, raw)

	resp, err := backend.handleSkillUpdate(ctx, req, fd)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestSystemBackend_HandleSkillDelete_Success(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)
	schema, _ := skillPathSchemas(backend)

	createRaw := validSkillFields("trash")
	createReq := createTestRequest(logical.CreateOperation, "skills/trash", createRaw)
	createFD := createFieldData(schema, createRaw)
	_, err := backend.handleSkillCreate(ctx, createReq, createFD)
	require.NoError(t, err)

	deleteReq := createTestRequest(logical.DeleteOperation, "skills/trash", createRaw)
	resp, err := backend.handleSkillDelete(ctx, deleteReq, createFD)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Confirm gone.
	readResp, _ := backend.handleSkillRead(ctx, deleteReq, createFD)
	assert.Equal(t, http.StatusNotFound, readResp.StatusCode)
}

func TestSystemBackend_HandleSkillDelete_NotFound(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)
	schema, _ := skillPathSchemas(backend)
	raw := map[string]interface{}{"name": "ghost"}
	req := createTestRequest(logical.DeleteOperation, "skills/ghost", raw)
	fd := createFieldData(schema, raw)

	resp, err := backend.handleSkillDelete(ctx, req, fd)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestSystemBackend_HandleSkillList_OmitsBody(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)
	crudSchema, listSchema := skillPathSchemas(backend)

	for _, name := range []string{"alpha", "bravo"} {
		raw := validSkillFields(name)
		req := createTestRequest(logical.CreateOperation, "skills/"+name, raw)
		fd := createFieldData(crudSchema, raw)
		_, err := backend.handleSkillCreate(ctx, req, fd)
		require.NoError(t, err)
	}

	listReq := createTestRequest(logical.ListOperation, "skills/", nil)
	resp, err := backend.handleSkillList(ctx, listReq, createFieldData(listSchema, nil))
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	items, ok := resp.Data["skills"].([]map[string]any)
	require.True(t, ok)
	require.Len(t, items, 2)
	for _, item := range items {
		_, hasBody := item["body"]
		assert.False(t, hasBody, "LIST response must omit body for skill %v", item["name"])
		assert.NotEmpty(t, item["name"])
		assert.NotEmpty(t, item["description"])
	}
}

// nonRootContext returns a context bound to a non-root namespace.
func nonRootContext(t *testing.T) context.Context {
	t.Helper()
	ns := &namespace.Namespace{
		ID:   "child-namespace-id",
		Path: "child/",
		UUID: "child-uuid",
	}
	return namespace.ContextWithNamespace(context.Background(), ns)
}

func TestSystemBackend_HandleSkillCreate_RejectsNonRootNamespace(t *testing.T) {
	backend, _, _ := setupTestSystemBackend(t)
	schema, _ := skillPathSchemas(backend)
	raw := validSkillFields("nope")
	req := createTestRequest(logical.CreateOperation, "skills/nope", raw)
	fd := createFieldData(schema, raw)

	resp, err := backend.handleSkillCreate(nonRootContext(t), req, fd)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestSystemBackend_HandleSkillUpdate_RejectsNonRootNamespace(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)
	schema, _ := skillPathSchemas(backend)

	createRaw := validSkillFields("existing")
	createReq := createTestRequest(logical.CreateOperation, "skills/existing", createRaw)
	createFD := createFieldData(schema, createRaw)
	_, err := backend.handleSkillCreate(ctx, createReq, createFD)
	require.NoError(t, err)

	updateRaw := map[string]interface{}{"name": "existing", "description": "child override"}
	updateReq := createTestRequest(logical.UpdateOperation, "skills/existing", updateRaw)
	updateFD := createFieldData(schema, updateRaw)

	resp, err := backend.handleSkillUpdate(nonRootContext(t), updateReq, updateFD)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestSystemBackend_HandleSkillDelete_RejectsNonRootNamespace(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)
	schema, _ := skillPathSchemas(backend)

	createRaw := validSkillFields("guarded")
	createReq := createTestRequest(logical.CreateOperation, "skills/guarded", createRaw)
	createFD := createFieldData(schema, createRaw)
	_, err := backend.handleSkillCreate(ctx, createReq, createFD)
	require.NoError(t, err)

	deleteReq := createTestRequest(logical.DeleteOperation, "skills/guarded", createRaw)
	resp, err := backend.handleSkillDelete(nonRootContext(t), deleteReq, createFD)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestSystemBackend_HandleSkillRead_AllowsAnyNamespace(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)
	schema, _ := skillPathSchemas(backend)

	createRaw := validSkillFields("publicly-visible")
	createReq := createTestRequest(logical.CreateOperation, "skills/publicly-visible", createRaw)
	createFD := createFieldData(schema, createRaw)
	_, err := backend.handleSkillCreate(ctx, createReq, createFD)
	require.NoError(t, err)

	// Reading from a non-root namespace must succeed — skills are global,
	// read-open by design.
	readReq := createTestRequest(logical.ReadOperation, "skills/publicly-visible", createRaw)
	resp, err := backend.handleSkillRead(nonRootContext(t), readReq, createFD)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "publicly-visible", resp.Data["name"])
}

func TestSystemBackend_HandleSkillList_AllowsAnyNamespace(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)
	crudSchema, listSchema := skillPathSchemas(backend)

	createRaw := validSkillFields("listed")
	createReq := createTestRequest(logical.CreateOperation, "skills/listed", createRaw)
	createFD := createFieldData(crudSchema, createRaw)
	_, err := backend.handleSkillCreate(ctx, createReq, createFD)
	require.NoError(t, err)

	listReq := createTestRequest(logical.ListOperation, "skills/", nil)
	resp, err := backend.handleSkillList(nonRootContext(t), listReq, createFieldData(listSchema, nil))
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
