package core

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	require.Len(t, paths, 6) // sources CRUD, sources list, specs CRUD, specs list, specs authorize, specs connect

	// Check sources/{name} path
	assert.Equal(t, "cred/sources/"+framework.GenericNameRegex("name"), paths[0].Pattern)

	// Check sources/ list path
	assert.Equal(t, "cred/sources/?$", paths[1].Pattern)

	// Check specs/{name} path
	assert.Equal(t, "cred/specs/"+framework.GenericNameRegex("name"), paths[2].Pattern)

	// Check specs/ list path
	assert.Equal(t, "cred/specs/?$", paths[3].Pattern)

	// Check specs connect-flow paths
	assert.Equal(t, "cred/specs/"+framework.GenericNameRegex("name")+"/authorize", paths[4].Pattern)
	assert.Equal(t, "cred/specs/"+framework.GenericNameRegex("name")+"/connect", paths[5].Pattern)
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

func TestSystemBackend_HandleCredentialSourceRead_NotFound(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)

	schema := backend.pathCredentials()[0].Fields
	raw := map[string]interface{}{
		"name": "nonexistent",
	}

	req := createTestRequest(logical.ReadOperation, "cred/sources/nonexistent", raw)
	fieldData := createFieldData(schema, raw)

	resp, err := backend.handleCredentialSourceRead(ctx, req, fieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestSystemBackend_HandleCredentialSourceUpdate_NotFound(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)

	schema := backend.pathCredentials()[0].Fields
	raw := map[string]interface{}{
		"name":   "nonexistent",
		"config": map[string]interface{}{"key": "value"},
	}

	req := createTestRequest(logical.UpdateOperation, "cred/sources/nonexistent", raw)
	fieldData := createFieldData(schema, raw)

	resp, err := backend.handleCredentialSourceUpdate(ctx, req, fieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
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

func TestSystemBackend_HandleCredentialSpecRead_NotFound(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)

	schema := backend.pathCredentials()[2].Fields
	raw := map[string]interface{}{
		"name": "nonexistent",
	}

	req := createTestRequest(logical.ReadOperation, "cred/specs/nonexistent", raw)
	fieldData := createFieldData(schema, raw)

	resp, err := backend.handleCredentialSpecRead(ctx, req, fieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestSystemBackend_HandleCredentialSpecUpdate_NotFound(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)

	schema := backend.pathCredentials()[2].Fields
	raw := map[string]interface{}{
		"name":    "nonexistent",
		"min_ttl": 3600,
	}

	req := createTestRequest(logical.UpdateOperation, "cred/specs/nonexistent", raw)
	fieldData := createFieldData(schema, raw)

	resp, err := backend.handleCredentialSpecUpdate(ctx, req, fieldData)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
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

// =============================================================================
// OAuth2 connect endpoints
// =============================================================================

// createOAuth2Source creates an oauth2 source with the given auth/token URLs.
func createOAuth2Source(t *testing.T, backend *SystemBackend, ctx context.Context, name, authURL, tokenURL string, tlsSkipVerify bool) {
	t.Helper()
	cfg := map[string]interface{}{"auth_url": authURL, "token_url": tokenURL}
	if tlsSkipVerify {
		cfg["tls_skip_verify"] = "true"
	}
	raw := map[string]interface{}{"name": name, "type": "oauth2", "config": cfg, "rotation_period": 0}
	schema := backend.pathCredentials()[0].Fields
	resp, err := backend.handleCredentialSourceCreate(ctx, createTestRequest(logical.CreateOperation, "cred/sources/"+name, raw), createFieldData(schema, raw))
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode, "source create: %+v", resp.Data)
}

// createAuthCodeSpec creates an empty authorization_code spec.
func createAuthCodeSpec(t *testing.T, backend *SystemBackend, ctx context.Context, name, source string, extraConfig map[string]string) {
	t.Helper()
	cfg := map[string]interface{}{"auth_method": "authorization_code", "client_id": "cid", "client_secret": "csecret"}
	for k, v := range extraConfig {
		cfg[k] = v
	}
	raw := map[string]interface{}{"name": name, "type": "oauth_bearer_token", "source": source, "config": cfg}
	schema := backend.pathCredentials()[2].Fields
	resp, err := backend.handleCredentialSpecCreate(ctx, createTestRequest(logical.CreateOperation, "cred/specs/"+name, raw), createFieldData(schema, raw))
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode, "spec create: %+v", resp.Data)
}

func TestSystemBackend_HandleCredentialSpecAuthorize(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)
	createOAuth2Source(t, backend, ctx, "gh-src", "https://github.com/login/oauth/authorize", "https://github.com/login/oauth/access_token", false)
	createAuthCodeSpec(t, backend, ctx, "gh", "gh-src", map[string]string{"scopes": "repo,read:org"})

	schema := backend.pathCredentials()[4].Fields // .../authorize
	raw := map[string]interface{}{
		"name":           "gh",
		"redirect_uri":   "http://127.0.0.1:8765/callback",
		"state":          "the-state",
		"code_challenge": "the-challenge",
	}
	resp, err := backend.handleCredentialSpecAuthorize(ctx, createTestRequest(logical.CreateOperation, "cred/specs/gh/authorize", raw), createFieldData(schema, raw))
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Nil(t, resp.Err, "authorize error: %+v", resp.Data)

	authorizeURL, _ := resp.Data["authorize_url"].(string)
	u, err := url.Parse(authorizeURL)
	require.NoError(t, err)
	assert.Equal(t, "github.com", u.Host)
	q := u.Query()
	assert.Equal(t, "code", q.Get("response_type"))
	assert.Equal(t, "cid", q.Get("client_id"))
	assert.Equal(t, "http://127.0.0.1:8765/callback", q.Get("redirect_uri"))
	assert.Equal(t, "the-state", q.Get("state"))
	assert.Equal(t, "repo read:org", q.Get("scope"))
	assert.Equal(t, "the-challenge", q.Get("code_challenge"))
}

func TestSystemBackend_HandleCredentialSpecAuthorize_NotConnectGated(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)
	createOAuth2Source(t, backend, ctx, "cc-src", "https://idp/authorize", "https://idp/token", false)
	// A client_credentials spec is not connect-gated.
	raw := map[string]interface{}{"name": "cc", "type": "oauth_bearer_token", "source": "cc-src", "config": map[string]interface{}{"client_id": "x", "client_secret": "y"}}
	createResp, err := backend.handleCredentialSpecCreate(ctx, createTestRequest(logical.CreateOperation, "cred/specs/cc", raw), createFieldData(backend.pathCredentials()[2].Fields, raw))
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, createResp.StatusCode, "%+v", createResp.Data)

	schema := backend.pathCredentials()[4].Fields
	areq := map[string]interface{}{"name": "cc", "redirect_uri": "http://127.0.0.1:1/callback"}
	resp, err := backend.handleCredentialSpecAuthorize(ctx, createTestRequest(logical.CreateOperation, "cred/specs/cc/authorize", areq), createFieldData(schema, areq))
	require.NoError(t, err)
	require.NotNil(t, resp.Err)
	assert.Contains(t, resp.Err.Error(), "does not use an interactive connect flow")
}

func TestSystemBackend_HandleCredentialSpecAuthorize_BadRedirectURI(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)
	createOAuth2Source(t, backend, ctx, "gh-src", "https://github.com/login/oauth/authorize", "https://github.com/login/oauth/access_token", false)
	createAuthCodeSpec(t, backend, ctx, "gh", "gh-src", nil)

	schema := backend.pathCredentials()[4].Fields
	raw := map[string]interface{}{"name": "gh", "redirect_uri": "https://evil.example.com/callback"} // not loopback
	resp, err := backend.handleCredentialSpecAuthorize(ctx, createTestRequest(logical.CreateOperation, "cred/specs/gh/authorize", raw), createFieldData(schema, raw))
	require.NoError(t, err)
	require.NotNil(t, resp.Err)
	assert.Contains(t, resp.Err.Error(), "loopback")
}

func TestSystemBackend_HandleCredentialSpecConnect(t *testing.T) {
	// Mock token endpoint returns a refresh token.
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		assert.Equal(t, "authorization_code", r.Form.Get("grant_type"))
		assert.Equal(t, "the-code", r.Form.Get("code"))
		assert.Equal(t, "csecret", r.Form.Get("client_secret")) // server holds the secret
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "at", "refresh_token": "rt-sealed", "expires_in": 28800})
	}))
	defer server.Close()

	backend, ctx, _ := setupTestSystemBackend(t)
	createOAuth2Source(t, backend, ctx, "gh-src", "https://github.com/login/oauth/authorize", server.URL, true)
	createAuthCodeSpec(t, backend, ctx, "gh", "gh-src", nil)

	schema := backend.pathCredentials()[5].Fields // .../connect
	raw := map[string]interface{}{
		"name":          "gh",
		"code":          "the-code",
		"redirect_uri":  "http://127.0.0.1:8765/callback",
		"code_verifier": "the-verifier",
	}
	resp, err := backend.handleCredentialSpecConnect(ctx, createTestRequest(logical.CreateOperation, "cred/specs/gh/connect", raw), createFieldData(schema, raw))
	require.NoError(t, err)
	require.Nil(t, resp.Err, "connect error: %+v", resp.Data)
	assert.Equal(t, true, resp.Data["connected"])
	assert.Equal(t, false, resp.Data["reconnected"])

	// The refresh token is sealed into the spec.
	spec, err := backend.core.credConfigStore.GetSpec(ctx, "gh")
	require.NoError(t, err)
	assert.Equal(t, "rt-sealed", spec.Config["refresh_token"])

	// Re-running reports reconnected=true.
	resp2, err := backend.handleCredentialSpecConnect(ctx, createTestRequest(logical.CreateOperation, "cred/specs/gh/connect", raw), createFieldData(schema, raw))
	require.NoError(t, err)
	require.Nil(t, resp2.Err)
	assert.Equal(t, true, resp2.Data["reconnected"])
}

func TestSystemBackend_HandleCredentialSpecConnect_MissingCode(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)
	createOAuth2Source(t, backend, ctx, "gh-src", "https://github.com/login/oauth/authorize", "https://github.com/login/oauth/access_token", false)
	createAuthCodeSpec(t, backend, ctx, "gh", "gh-src", nil)

	schema := backend.pathCredentials()[5].Fields
	raw := map[string]interface{}{"name": "gh", "redirect_uri": "http://127.0.0.1:8765/callback"} // no code
	resp, err := backend.handleCredentialSpecConnect(ctx, createTestRequest(logical.CreateOperation, "cred/specs/gh/connect", raw), createFieldData(schema, raw))
	require.NoError(t, err)
	require.NotNil(t, resp.Err)
	assert.Contains(t, resp.Err.Error(), "code is required")
}

func TestSystemBackend_HandleCredentialSpecConnect_ExchangeError(t *testing.T) {
	// Provider rejects the code (GitHub-style HTTP 200 with an error body).
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "bad_verification_code", "error_description": "The code passed is incorrect or expired."})
	}))
	defer server.Close()

	backend, ctx, _ := setupTestSystemBackend(t)
	createOAuth2Source(t, backend, ctx, "gh-src", "https://github.com/login/oauth/authorize", server.URL, true)
	createAuthCodeSpec(t, backend, ctx, "gh", "gh-src", nil)

	schema := backend.pathCredentials()[5].Fields
	raw := map[string]interface{}{"name": "gh", "code": "stale-code", "redirect_uri": "http://127.0.0.1:8765/callback"}
	resp, err := backend.handleCredentialSpecConnect(ctx, createTestRequest(logical.CreateOperation, "cred/specs/gh/connect", raw), createFieldData(schema, raw))
	require.NoError(t, err)
	require.NotNil(t, resp.Err, "exchange failure must surface as an error response")

	// The spec must NOT be marked connected after a failed exchange.
	spec, err := backend.core.credConfigStore.GetSpec(ctx, "gh")
	require.NoError(t, err)
	assert.Empty(t, spec.Config["refresh_token"])
}

func TestSystemBackend_HandleCredentialSpecAuthorize_PinnedRedirectURI(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)
	createOAuth2Source(t, backend, ctx, "gh-src", "https://github.com/login/oauth/authorize", "https://github.com/login/oauth/access_token", false)
	// Pin a fixed loopback redirect_uri on the spec.
	createAuthCodeSpec(t, backend, ctx, "gh", "gh-src", map[string]string{"redirect_uri": "http://127.0.0.1:8765/callback"})

	schema := backend.pathCredentials()[4].Fields

	// Matching redirect_uri is accepted.
	ok := map[string]interface{}{"name": "gh", "redirect_uri": "http://127.0.0.1:8765/callback", "state": "s"}
	resp, err := backend.handleCredentialSpecAuthorize(ctx, createTestRequest(logical.CreateOperation, "cred/specs/gh/authorize", ok), createFieldData(schema, ok))
	require.NoError(t, err)
	require.Nil(t, resp.Err, "pinned match must succeed: %+v", resp.Data)

	// A different loopback port is rejected even though it is loopback.
	bad := map[string]interface{}{"name": "gh", "redirect_uri": "http://127.0.0.1:9999/callback", "state": "s"}
	resp, err = backend.handleCredentialSpecAuthorize(ctx, createTestRequest(logical.CreateOperation, "cred/specs/gh/authorize", bad), createFieldData(schema, bad))
	require.NoError(t, err)
	require.NotNil(t, resp.Err)
	assert.Contains(t, resp.Err.Error(), "does not match")
}
