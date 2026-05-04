package core

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/framework"
)

// TestOpenAPI_Endpoint_RegisteredPaths confirms the system backend exposes
// both the canonical Vault-compatible path and the agent-friendly alias.
func TestOpenAPI_Endpoint_RegisteredPaths(t *testing.T) {
	backend, _, _ := setupTestSystemBackend(t)

	paths := backend.pathOpenAPI()
	require.Len(t, paths, 2, "expected canonical + alias paths")

	patterns := map[string]bool{}
	for _, p := range paths {
		patterns[p.Pattern] = true
	}
	require.True(t, patterns["internal/specs/openapi"], "missing canonical path")
	require.True(t, patterns["schema"], "missing agent-friendly alias")
}

// TestOpenAPI_Endpoint_ReturnsDocument confirms the handler returns a non-empty
// OpenAPI document and includes the system backend's own sys/* paths (which
// would be missing if the explicit document-system-backend step were omitted).
func TestOpenAPI_Endpoint_ReturnsDocument(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)

	schema := backend.pathOpenAPI()[0].Fields
	fieldData := createFieldData(schema, map[string]any{})
	req := createTestRequest("read", "internal/specs/openapi", nil)

	resp, err := backend.handleOpenAPI(ctx, req, fieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError(), "unexpected error response: %v", resp.Data)

	doc, ok := resp.Data["openapi"].(*framework.OASDocument)
	require.True(t, ok, "expected *OASDocument under .openapi, got %T", resp.Data["openapi"])
	require.NotEmpty(t, doc.Paths, "OpenAPI doc has no paths — system backend was likely not documented")

	hasSys := false
	for p := range doc.Paths {
		if strings.HasPrefix(p, "/sys/") || strings.HasPrefix(p, "sys/") {
			hasSys = true
			break
		}
	}
	require.True(t, hasSys, "expected sys/* paths in OpenAPI doc; system backend not documented? paths: %v", pathKeys(doc))
}

// TestOpenAPI_Endpoint_PathProjection confirms that ?path=PATH narrows the
// document to a single operation when the path exists.
func TestOpenAPI_Endpoint_PathProjection(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)
	schema := backend.pathOpenAPI()[0].Fields

	// First fetch the full doc, pick any path the test core has, then query
	// it back via projection. This makes the test resilient to the exact set
	// of paths the system backend exposes.
	full, err := backend.handleOpenAPI(ctx, createTestRequest("read", "internal/specs/openapi", nil), createFieldData(schema, map[string]any{}))
	require.NoError(t, err)
	doc := full.Data["openapi"].(*framework.OASDocument)

	var anyPath string
	for p := range doc.Paths {
		anyPath = p
		break
	}
	require.NotEmpty(t, anyPath, "test core has no documented paths")

	fieldData := createFieldData(schema, map[string]any{"path": strings.TrimPrefix(anyPath, "/")})
	resp, err := backend.handleOpenAPI(ctx, createTestRequest("read", "internal/specs/openapi", nil), fieldData)
	require.NoError(t, err)
	require.False(t, resp.IsError(), "projection returned error for known path %q: %v", anyPath, resp.Data)

	projected := resp.Data["openapi"].(*framework.OASDocument)
	require.Len(t, projected.Paths, 1, "projection should return exactly one path; got %v", pathKeys(projected))
}

// TestOpenAPI_Endpoint_PathProjection_Unknown confirms that ?path=PATH with a
// non-existent path returns a structured error (not a 200 with empty paths,
// which would silently mislead agents).
func TestOpenAPI_Endpoint_PathProjection_Unknown(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)
	schema := backend.pathOpenAPI()[0].Fields

	fieldData := createFieldData(schema, map[string]any{"path": "definitely/not/a/real/path"})
	resp, err := backend.handleOpenAPI(ctx, createTestRequest("read", "internal/specs/openapi", nil), fieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.True(t, resp.IsError(), "expected error response for unknown projection path")
}

// TestOpenAPI_AliasAndCanonicalAreEquivalent verifies that the agent-friendly
// alias `sys/schema` produces the same content as the canonical path.
func TestOpenAPI_AliasAndCanonicalAreEquivalent(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)
	schemaCanonical := backend.pathOpenAPI()[0].Fields
	schemaAlias := backend.pathOpenAPI()[1].Fields

	canonical, err := backend.handleOpenAPI(ctx, createTestRequest("read", "internal/specs/openapi", nil), createFieldData(schemaCanonical, map[string]any{}))
	require.NoError(t, err)
	alias, err := backend.handleOpenAPI(ctx, createTestRequest("read", "schema", nil), createFieldData(schemaAlias, map[string]any{}))
	require.NoError(t, err)

	cBytes, err := json.Marshal(canonical.Data["openapi"])
	require.NoError(t, err)
	aBytes, err := json.Marshal(alias.Data["openapi"])
	require.NoError(t, err)

	require.JSONEq(t, string(cBytes), string(aBytes), "canonical and alias must return identical content")
}

func pathKeys(doc *framework.OASDocument) []string {
	keys := make([]string, 0, len(doc.Paths))
	for k := range doc.Paths {
		keys = append(keys, k)
	}
	return keys
}
