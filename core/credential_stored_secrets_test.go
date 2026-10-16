package core

import (
	"context"
	"net/http"
	"testing"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/internal/namespace"
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

	createSourceForTest(t, backend, ctx, keyedHvaultSource("keyed"))
	createSourceForTest(t, backend, ctx, keylessHvaultSource("keyless"))

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

	// token is masked like secret_id but optional beside approle, so it can be
	// cleared on its own.
	keyed := keyedHvaultSource("vault-src")
	keyed["config"].(map[string]interface{})["token"] = "real-token"
	createSourceForTest(t, backend, ctx, keyed)

	updateRaw := map[string]interface{}{
		"name":   "vault-src",
		"config": map[string]interface{}{"token": ""},
	}
	resp, err := backend.handleCredentialSourceUpdate(ctx,
		createTestRequest(logical.UpdateOperation, "cred/sources/vault-src", updateRaw),
		createFieldData(backend.pathCredentials()[0].Fields, updateRaw))
	require.NoError(t, err)
	require.Equalf(t, http.StatusOK, resp.StatusCode, "update: %+v", resp.Data)

	data := readSourceForTest(t, backend, ctx, "vault-src")
	assert.Equal(t, "", data["config"].(map[string]string)["token"])
	assert.Equal(t, maskValue, data["config"].(map[string]string)["secret_id"])
	assert.Equal(t, []string{"secret_id"}, data["stored_secrets"])
}

// A source stored before auth_method became required has no credential of its
// own and logs in with the server environment's token. It still loads and reads
// back, the environment token is reported as the secret it holds, and an edit is
// refused until it sets auth_method — which is what stops an edit from pointing
// that token at a new vault_address.
func TestStoredSecrets_LegacyEnvTokenSource(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)

	ns, err := namespace.FromContext(ctx)
	require.NoError(t, err)
	require.NoError(t, backend.core.credConfigStore.persistSource(ns.UUID, &credential.CredSource{
		Name:   "legacy",
		Type:   "hvault",
		Config: credential.NewConfig(map[string]string{"vault_address": "https://vault.example.com"}),
	}))

	data := readSourceForTest(t, backend, ctx, "legacy")
	assert.Equal(t, []string{"vault token from the server environment"}, data["stored_secrets"])

	updateRaw := map[string]interface{}{
		"name":   "legacy",
		"config": map[string]interface{}{"vault_address": "https://elsewhere.example.com"},
	}
	resp, err := backend.handleCredentialSourceUpdate(ctx,
		createTestRequest(logical.UpdateOperation, "cred/sources/legacy", updateRaw),
		createFieldData(backend.pathCredentials()[0].Fields, updateRaw))
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, "%+v", resp.Data)
	assert.Contains(t, resp.Err.Error(), "auth_method")

	stored, err := backend.core.credConfigStore.GetSource(ctx, "legacy")
	require.NoError(t, err)
	assert.Equal(t, "https://vault.example.com", stored.Config.Get("vault_address"), "the refused edit changed nothing")
}
