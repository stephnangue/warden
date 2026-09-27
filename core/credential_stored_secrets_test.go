package core

import (
	"context"
	"net/http"
	"testing"

	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createSourceForTest creates a source through the handler and fails the test on
// any refusal, since the handler reports those in the response.
func createSourceForTest(t *testing.T, backend *SystemBackend, ctx context.Context, raw map[string]interface{}) {
	t.Helper()
	name := raw["name"].(string)
	resp, err := backend.handleCredentialSourceCreate(ctx,
		createTestRequest(logical.CreateOperation, "cred/sources/"+name, raw),
		createFieldData(backend.pathCredentials()[0].Fields, raw))
	require.NoError(t, err)
	require.Equalf(t, http.StatusCreated, resp.StatusCode, "source %q create: %+v", name, resp.Data)
}

// createSpecForTest is createSourceForTest for specs.
func createSpecForTest(t *testing.T, backend *SystemBackend, ctx context.Context, raw map[string]interface{}) {
	t.Helper()
	name := raw["name"].(string)
	resp, err := backend.handleCredentialSpecCreate(ctx,
		createTestRequest(logical.CreateOperation, "cred/specs/"+name, raw),
		createFieldData(backend.pathCredentials()[2].Fields, raw))
	require.NoError(t, err)
	require.Equalf(t, http.StatusCreated, resp.StatusCode, "spec %q create: %+v", name, resp.Data)
}

func readSourceForTest(t *testing.T, backend *SystemBackend, ctx context.Context, name string) map[string]any {
	t.Helper()
	raw := map[string]interface{}{"name": name}
	resp, err := backend.handleCredentialSourceRead(ctx,
		createTestRequest(logical.ReadOperation, "cred/sources/"+name, raw),
		createFieldData(backend.pathCredentials()[0].Fields, raw))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	return resp.Data
}

func readSpecForTest(t *testing.T, backend *SystemBackend, ctx context.Context, name string) map[string]any {
	t.Helper()
	raw := map[string]interface{}{"name": name}
	resp, err := backend.handleCredentialSpecRead(ctx,
		createTestRequest(logical.ReadOperation, "cred/specs/"+name, raw),
		createFieldData(backend.pathCredentials()[2].Fields, raw))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	return resp.Data
}

func TestStoredSecrets_SourceReadAndList(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)

	createSourceForTest(t, backend, ctx, map[string]interface{}{
		"name":            "keyed",
		"type":            "hvault",
		"rotation_period": 86400,
		"config": map[string]interface{}{
			"vault_address": "http://localhost:8200",
			"secret_id":     "real-secret-id",
		},
	})
	createSourceForTest(t, backend, ctx, map[string]interface{}{
		"name": "keyless",
		"type": "hvault",
		"config": map[string]interface{}{
			"vault_address": "http://localhost:8200",
			"auth_method":   "oidc_federation",
			"jwt_role":      "agents",
		},
	})

	keyed := readSourceForTest(t, backend, ctx, "keyed")
	assert.Equal(t, []string{"secret_id"}, keyed["stored_secrets"])
	assert.NotContains(t, keyed["stored_secrets"], "real-secret-id", "stored_secrets must carry names, never values")

	keyless := readSourceForTest(t, backend, ctx, "keyless")
	assert.NotContains(t, keyless, "stored_secrets")

	listResp, err := backend.handleCredentialSourceList(ctx,
		createTestRequest(logical.ListOperation, "cred/sources", nil), nil)
	require.NoError(t, err)
	byName := map[string]map[string]any{}
	for _, item := range listResp.Data["sources"].([]map[string]any) {
		byName[item["name"].(string)] = item
	}
	assert.Equal(t, []string{"secret_id"}, byName["keyed"]["stored_secrets"])
	assert.NotContains(t, byName["keyless"], "stored_secrets")
}

func TestStoredSecrets_SpecReadAndList(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)

	createSourceForTest(t, backend, ctx, map[string]interface{}{
		"name": "apikey-src",
		"type": "apikey",
	})
	createSpecForTest(t, backend, ctx, map[string]interface{}{
		"name":   "inline-key",
		"type":   "api_key",
		"source": "apikey-src",
		"config": map[string]interface{}{"api_key": "sk-real-secret"},
	})
	createHVaultSource(t, backend, ctx, "vault-src")
	createSpecForTest(t, backend, ctx, map[string]interface{}{
		"name":   "vault-token",
		"type":   "vault_token",
		"source": "vault-src",
		"config": map[string]interface{}{"mint_method": "vault_token", "token_role": "r"},
	})

	inline := readSpecForTest(t, backend, ctx, "inline-key")
	assert.Equal(t, []string{"api_key"}, inline["stored_secrets"])

	// The spec entry judges the spec's own config, not its source's.
	vaultToken := readSpecForTest(t, backend, ctx, "vault-token")
	assert.NotContains(t, vaultToken, "stored_secrets")

	listResp, err := backend.handleCredentialSpecList(ctx,
		createTestRequest(logical.ListOperation, "cred/specs", nil), nil)
	require.NoError(t, err)
	byName := map[string]map[string]any{}
	for _, item := range listResp.Data["specs"].([]map[string]any) {
		byName[item["name"].(string)] = item
	}
	assert.Equal(t, []string{"api_key"}, byName["inline-key"]["stored_secrets"])
	assert.NotContains(t, byName["vault-token"], "stored_secrets")
}

// A secret cleared to "" must read back as "", not the mask: masking it would
// show a secret still held beside a stored_secrets that says otherwise.
func TestStoredSecrets_ClearedSecretReadsBackEmpty(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)

	createSourceForTest(t, backend, ctx, map[string]interface{}{
		"name":            "vault-src",
		"type":            "hvault",
		"rotation_period": 86400,
		"config": map[string]interface{}{
			"vault_address": "http://localhost:8200",
			"secret_id":     "real-secret-id",
		},
	})

	updateRaw := map[string]interface{}{
		"name":   "vault-src",
		"config": map[string]interface{}{"secret_id": ""},
	}
	resp, err := backend.handleCredentialSourceUpdate(ctx,
		createTestRequest(logical.UpdateOperation, "cred/sources/vault-src", updateRaw),
		createFieldData(backend.pathCredentials()[0].Fields, updateRaw))
	require.NoError(t, err)
	require.Equalf(t, http.StatusOK, resp.StatusCode, "update: %+v", resp.Data)

	data := readSourceForTest(t, backend, ctx, "vault-src")
	assert.Equal(t, "", data["config"].(map[string]string)["secret_id"])
	// No auth_method and no stored secret: the source falls back to the token in
	// the server's environment, which is still reported.
	assert.Equal(t, []string{"vault token from the server environment"}, data["stored_secrets"])
}
