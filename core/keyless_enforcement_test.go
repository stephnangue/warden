package core

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stephnangue/warden/config"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseKeylessEnforcementLevel(t *testing.T) {
	assert.Equal(t, KeylessEnforcementWarn, parseKeylessEnforcementLevel(nil), "no config is warn")
	assert.Equal(t, KeylessEnforcementWarn, parseKeylessEnforcementLevel(&config.Config{}), "an absent key is warn")
	for _, level := range []KeylessEnforcementLevel{KeylessEnforcementOff, KeylessEnforcementWarn, KeylessEnforcementEnforce} {
		assert.Equal(t, level, parseKeylessEnforcementLevel(&config.Config{KeylessEnforcementLevel: string(level)}))
	}
}

func TestCheckKeyless(t *testing.T) {
	secrets := []string{"secret_access_key"}

	for _, tc := range []struct {
		level       KeylessEnforcementLevel
		secrets     []string
		wantWarning bool
		wantErr     bool
	}{
		{KeylessEnforcementOff, secrets, false, false},
		{KeylessEnforcementWarn, secrets, true, false},
		{KeylessEnforcementEnforce, secrets, false, true},
		{KeylessEnforcementWarn, nil, false, false},
		{KeylessEnforcementEnforce, nil, false, false},
	} {
		c := &Core{keylessEnforcement: tc.level}
		warnings, err := c.checkKeyless(keylessKindSource, "aws-prod", tc.secrets)
		assert.Equalf(t, tc.wantErr, err != nil, "level %s, secrets %v: err %v", tc.level, tc.secrets, err)
		assert.Equalf(t, tc.wantWarning, len(warnings) > 0, "level %s, secrets %v: warnings %v", tc.level, tc.secrets, warnings)
	}

	c := &Core{keylessEnforcement: KeylessEnforcementEnforce}
	_, err := c.checkKeyless(keylessKindSource, "aws-prod", []string{"secret_access_key", "ca_data"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `credential source "aws-prod"`)
	assert.Contains(t, err.Error(), "secret_access_key, ca_data")
	assert.Contains(t, err.Error(), "auth_method=oidc_federation", "a source refusal points at the source-level ways out")

	_, err = c.checkKeyless(keylessKindSpec, "gh", []string{"token"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "subject_token_source", "a spec refusal points at the spec-level ways out")
}

// keyedHvaultSource is an hvault source that stores a secret_id.
func keyedHvaultSource(name string) map[string]interface{} {
	return map[string]interface{}{
		"name":            name,
		"type":            "hvault",
		"rotation_period": 86400,
		"config": map[string]interface{}{
			"vault_address": "http://localhost:8200",
			"secret_id":     "real-secret-id",
		},
	}
}

// keylessHvaultSource is an hvault source that federates and stores nothing.
func keylessHvaultSource(name string) map[string]interface{} {
	return map[string]interface{}{
		"name": name,
		"type": "hvault",
		"config": map[string]interface{}{
			"vault_address": "http://localhost:8200",
			"auth_method":   "oidc_federation",
			"jwt_role":      "agents",
		},
	}
}

func sourceWrite(t *testing.T, backend *SystemBackend, ctx context.Context, op logical.Operation, raw map[string]interface{}) *logical.Response {
	t.Helper()
	name := raw["name"].(string)
	req := createTestRequest(op, "cred/sources/"+name, raw)
	fd := createFieldData(backend.pathCredentials()[0].Fields, raw)
	var resp *logical.Response
	var err error
	if op == logical.CreateOperation {
		resp, err = backend.handleCredentialSourceCreate(ctx, req, fd)
	} else {
		resp, err = backend.handleCredentialSourceUpdate(ctx, req, fd)
	}
	require.NoError(t, err)
	return resp
}

func specWrite(t *testing.T, backend *SystemBackend, ctx context.Context, op logical.Operation, raw map[string]interface{}) *logical.Response {
	t.Helper()
	name := raw["name"].(string)
	req := createTestRequest(op, "cred/specs/"+name, raw)
	fd := createFieldData(backend.pathCredentials()[2].Fields, raw)
	var resp *logical.Response
	var err error
	if op == logical.CreateOperation {
		resp, err = backend.handleCredentialSpecCreate(ctx, req, fd)
	} else {
		resp, err = backend.handleCredentialSpecUpdate(ctx, req, fd)
	}
	require.NoError(t, err)
	return resp
}

// requireKeylessRefusal asserts a 400 that names the setting.
func requireKeylessRefusal(t *testing.T, resp *logical.Response) {
	t.Helper()
	require.Equalf(t, http.StatusBadRequest, resp.StatusCode, "expected a keyless refusal, got %+v", resp.Data)
	require.NotNil(t, resp.Err)
	assert.Contains(t, resp.Err.Error(), "keyless_enforcement_level=enforce refuses")
}

func keylessWarnings(resp *logical.Response) []string {
	var out []string
	w, _ := resp.Data["warnings"].([]string)
	for _, s := range w {
		if strings.Contains(s, "keyless_enforcement_level") {
			out = append(out, s)
		}
	}
	return out
}

func TestKeylessEnforcement_SourceCreate(t *testing.T) {
	t.Run("off accepts silently", func(t *testing.T) {
		backend, ctx, _ := setupTestSystemBackend(t)
		backend.core.keylessEnforcement = KeylessEnforcementOff
		resp := sourceWrite(t, backend, ctx, logical.CreateOperation, keyedHvaultSource("keyed"))
		require.Equal(t, http.StatusCreated, resp.StatusCode, "%+v", resp.Data)
		assert.Empty(t, keylessWarnings(resp))
	})

	t.Run("warn accepts with a warning", func(t *testing.T) {
		backend, ctx, _ := setupTestSystemBackend(t)
		backend.core.keylessEnforcement = KeylessEnforcementWarn
		resp := sourceWrite(t, backend, ctx, logical.CreateOperation, keyedHvaultSource("keyed"))
		require.Equal(t, http.StatusCreated, resp.StatusCode, "%+v", resp.Data)
		w := keylessWarnings(resp)
		require.Len(t, w, 1)
		assert.Contains(t, w[0], "secret_id")
	})

	t.Run("enforce refuses and persists nothing", func(t *testing.T) {
		backend, ctx, _ := setupTestSystemBackend(t)
		backend.core.keylessEnforcement = KeylessEnforcementEnforce
		requireKeylessRefusal(t, sourceWrite(t, backend, ctx, logical.CreateOperation, keyedHvaultSource("keyed")))
		_, err := backend.core.credConfigStore.GetSource(ctx, "keyed")
		assert.ErrorIs(t, err, ErrSourceNotFound)
	})

	t.Run("enforce accepts a keyless source without warning", func(t *testing.T) {
		backend, ctx, _ := setupTestSystemBackend(t)
		backend.core.keylessEnforcement = KeylessEnforcementEnforce
		resp := sourceWrite(t, backend, ctx, logical.CreateOperation, keylessHvaultSource("keyless"))
		require.Equal(t, http.StatusCreated, resp.StatusCode, "%+v", resp.Data)
		assert.Empty(t, keylessWarnings(resp))
	})
}

func TestKeylessEnforcement_SourceUpdate(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)
	backend.core.keylessEnforcement = KeylessEnforcementOff
	require.Equal(t, http.StatusCreated, sourceWrite(t, backend, ctx, logical.CreateOperation, keyedHvaultSource("legacy")).StatusCode)
	backend.core.keylessEnforcement = KeylessEnforcementEnforce

	// A cosmetic edit that leaves the secret in place is refused, and the
	// stored config is untouched.
	requireKeylessRefusal(t, sourceWrite(t, backend, ctx, logical.UpdateOperation, map[string]interface{}{
		"name":   "legacy",
		"config": map[string]interface{}{"vault_address": "http://localhost:8300"},
	}))
	stored, err := backend.core.credConfigStore.GetSource(ctx, "legacy")
	require.NoError(t, err)
	assert.Equal(t, "http://localhost:8200", stored.Config.Get("vault_address"))

	// Resending the read-back mask keeps the secret, so it is refused too.
	requireKeylessRefusal(t, sourceWrite(t, backend, ctx, logical.UpdateOperation, map[string]interface{}{
		"name":   "legacy",
		"config": map[string]interface{}{"secret_id": maskValue},
	}))

	// Migrating in place — keyless mode, secret cleared, rotation off — passes.
	resp := sourceWrite(t, backend, ctx, logical.UpdateOperation, map[string]interface{}{
		"name":            "legacy",
		"rotation_period": 0,
		"config": map[string]interface{}{
			"auth_method": "oidc_federation",
			"jwt_role":    "agents",
			"secret_id":   "",
		},
	})
	require.Equal(t, http.StatusOK, resp.StatusCode, "%+v", resp.Data)
	assert.Empty(t, keylessWarnings(resp))
	stored, err = backend.core.credConfigStore.GetSource(ctx, "legacy")
	require.NoError(t, err)
	assert.Nil(t, backend.core.sourceStoredSecrets(stored.Type, stored.Config))
}

func TestKeylessEnforcement_SpecCreateOnKeyedSource(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)
	backend.core.keylessEnforcement = KeylessEnforcementOff
	require.Equal(t, http.StatusCreated, sourceWrite(t, backend, ctx, logical.CreateOperation, keyedHvaultSource("legacy")).StatusCode)
	backend.core.keylessEnforcement = KeylessEnforcementEnforce

	// A vault_token spec holds nothing itself, but a new one widens the use of
	// the source's stored secret.
	resp := specWrite(t, backend, ctx, logical.CreateOperation, map[string]interface{}{
		"name":   "tok",
		"type":   "vault_token",
		"source": "legacy",
		"config": map[string]interface{}{"mint_method": "vault_token", "token_role": "r"},
	})
	requireKeylessRefusal(t, resp)
	assert.Contains(t, resp.Err.Error(), `source "legacy": secret_id`)
	_, err := backend.core.credConfigStore.GetSpec(ctx, "tok")
	assert.ErrorIs(t, err, ErrSpecNotFound)
}

func TestKeylessEnforcement_SpecUpdate(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)
	backend.core.keylessEnforcement = KeylessEnforcementOff
	require.Equal(t, http.StatusCreated, sourceWrite(t, backend, ctx, logical.CreateOperation, keyedHvaultSource("legacy")).StatusCode)
	require.Equal(t, http.StatusCreated, specWrite(t, backend, ctx, logical.CreateOperation, map[string]interface{}{
		"name":   "tok",
		"type":   "vault_token",
		"source": "legacy",
		"config": map[string]interface{}{"mint_method": "vault_token", "token_role": "r"},
	}).StatusCode)
	require.Equal(t, http.StatusCreated, sourceWrite(t, backend, ctx, logical.CreateOperation, map[string]interface{}{
		"name": "apikey-src", "type": "apikey",
	}).StatusCode)
	require.Equal(t, http.StatusCreated, specWrite(t, backend, ctx, logical.CreateOperation, map[string]interface{}{
		"name":   "inline",
		"type":   "api_key",
		"source": "apikey-src",
		"config": map[string]interface{}{"api_key": "sk-real"},
	}).StatusCode)
	backend.core.keylessEnforcement = KeylessEnforcementEnforce

	// A keyless spec on a keyed source: the source is judged on its own writes,
	// so a TTL edit here goes through.
	resp := specWrite(t, backend, ctx, logical.UpdateOperation, map[string]interface{}{"name": "tok", "max_ttl": 7200})
	require.Equal(t, http.StatusOK, resp.StatusCode, "%+v", resp.Data)

	// A spec that holds its own secret is refused until the secret moves out.
	resp = specWrite(t, backend, ctx, logical.UpdateOperation, map[string]interface{}{"name": "inline", "max_ttl": 7200})
	requireKeylessRefusal(t, resp)
	stored, err := backend.core.credConfigStore.GetSpec(ctx, "inline")
	require.NoError(t, err)
	assert.NotEqual(t, int64(7200), int64(stored.MaxTTL.Seconds()), "a refused update must not persist")
}

func TestKeylessEnforcement_LocalSource(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)
	backend.core.keylessEnforcement = KeylessEnforcementOff
	localSpec := map[string]interface{}{
		"name":   "local-key",
		"type":   "api_key",
		"source": "local",
		"config": map[string]interface{}{"api_key": "sk-real"},
	}
	require.Equal(t, http.StatusCreated, specWrite(t, backend, ctx, logical.CreateOperation, localSpec).StatusCode)
	backend.core.keylessEnforcement = KeylessEnforcementEnforce

	localSpec["name"] = "local-key-2"
	resp := specWrite(t, backend, ctx, logical.CreateOperation, localSpec)
	requireKeylessRefusal(t, resp)
	assert.Contains(t, resp.Err.Error(), localSourceSecret)

	resp = specWrite(t, backend, ctx, logical.UpdateOperation, map[string]interface{}{"name": "local-key", "max_ttl": 7200})
	requireKeylessRefusal(t, resp)
	assert.Contains(t, resp.Err.Error(), localSourceSecret)
}

func TestKeylessEnforcement_AuthorizationCode(t *testing.T) {
	var exchanges atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		exchanges.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "at", "refresh_token": "rt", "expires_in": 3600})
	}))
	defer server.Close()

	backend, ctx, _ := setupTestSystemBackend(t)
	backend.core.keylessEnforcement = KeylessEnforcementOff
	createOAuth2Source(t, backend, ctx, "gh-src", "https://github.com/login/oauth/authorize", server.URL, true)
	createAuthCodeSpec(t, backend, ctx, "legacy", "gh-src", nil)
	backend.core.keylessEnforcement = KeylessEnforcementEnforce

	t.Run("create refuses", func(t *testing.T) {
		resp := specWrite(t, backend, ctx, logical.CreateOperation, map[string]interface{}{
			"name":   "new",
			"type":   "oauth_bearer_token",
			"source": "gh-src",
			"config": map[string]interface{}{"auth_method": "authorization_code", "client_id": "cid"},
		})
		requireKeylessRefusal(t, resp)
		assert.Contains(t, resp.Err.Error(), "refresh_token (sealed by connect)")
	})

	t.Run("authorize refuses", func(t *testing.T) {
		raw := map[string]interface{}{"name": "legacy", "redirect_uri": "http://127.0.0.1:8765/callback"}
		resp, err := backend.handleCredentialSpecAuthorize(ctx,
			createTestRequest(logical.CreateOperation, "cred/specs/legacy/authorize", raw),
			createFieldData(backend.pathCredentials()[4].Fields, raw))
		require.NoError(t, err)
		requireKeylessRefusal(t, resp)
	})

	t.Run("connect refuses before exchanging the code", func(t *testing.T) {
		raw := map[string]interface{}{
			"name":         "legacy",
			"code":         "the-code",
			"redirect_uri": "http://127.0.0.1:8765/callback",
		}
		resp, err := backend.handleCredentialSpecConnect(ctx,
			createTestRequest(logical.CreateOperation, "cred/specs/legacy/connect", raw),
			createFieldData(backend.pathCredentials()[5].Fields, raw))
		require.NoError(t, err)
		requireKeylessRefusal(t, resp)
		assert.Zero(t, exchanges.Load(), "the code must not be redeemed for a connect that is refused")
	})

	t.Run("warn connects with a warning", func(t *testing.T) {
		backend.core.keylessEnforcement = KeylessEnforcementWarn
		raw := map[string]interface{}{
			"name":         "legacy",
			"code":         "the-code",
			"redirect_uri": "http://127.0.0.1:8765/callback",
		}
		resp, err := backend.handleCredentialSpecConnect(ctx,
			createTestRequest(logical.CreateOperation, "cred/specs/legacy/connect", raw),
			createFieldData(backend.pathCredentials()[5].Fields, raw))
		require.NoError(t, err)
		require.Nil(t, resp.Err, "%+v", resp.Data)
		assert.Len(t, keylessWarnings(resp), 1)
		assert.Equal(t, int32(1), exchanges.Load())
	})
}

// Under warn, a spec that trips both the assertion_ttl warning and the keyless
// one reports both: neither overwrites the other.
func TestKeylessEnforcement_WarningsAccumulate(t *testing.T) {
	data := map[string]any{"warnings": []string{"assertion_ttl capped"}}
	appendWarnings(data, "keyless")
	appendWarnings(data)
	assert.Equal(t, []string{"assertion_ttl capped", "keyless"}, data["warnings"])

	empty := map[string]any{}
	appendWarnings(empty)
	assert.NotContains(t, empty, "warnings", "no warnings key when there is nothing to report")
}

// Internal writers are not gated: rotation writes a keyed source's new secret
// through the store, and must keep working after the level is raised.
func TestKeylessEnforcement_StoreWritesAreNotGated(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)
	backend.core.keylessEnforcement = KeylessEnforcementOff
	require.Equal(t, http.StatusCreated, sourceWrite(t, backend, ctx, logical.CreateOperation, keyedHvaultSource("legacy")).StatusCode)
	backend.core.keylessEnforcement = KeylessEnforcementEnforce

	existing, err := backend.core.credConfigStore.GetSource(ctx, "legacy")
	require.NoError(t, err)
	rotated := &credential.CredSource{
		Name:           existing.Name,
		Type:           existing.Type,
		Config:         existing.Config.With("secret_id", "rotated-secret-id"),
		RotationPeriod: existing.RotationPeriod,
	}
	require.NoError(t, backend.core.credConfigStore.UpdateSource(ctx, rotated, UpdateSourceOptions{SkipConnectionTest: true}))

	stored, err := backend.core.credConfigStore.GetSource(ctx, "legacy")
	require.NoError(t, err)
	assert.Equal(t, "rotated-secret-id", stored.Config.Get("secret_id"))
}
