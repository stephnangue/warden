package rest

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func apiKeyReq(t string, key string) *logical.Request {
	return &logical.Request{
		Credential: &credential.Credential{
			Type: t,
			Data: map[string]string{"api_key": key},
		},
	}
}

func TestTokenExtractor_DefaultBearer(t *testing.T) {
	headers, err := tokenExtractor("Authorization", "Bearer ", nil)(apiKeyReq(credential.TypeAPIKey, "sk-123"))
	require.NoError(t, err)
	assert.Equal(t, "Bearer sk-123", headers["Authorization"])
}

func TestTokenExtractor_AcceptsOAuthBearerType(t *testing.T) {
	// The oauth2 source mints TypeOAuthBearerToken but stores the token in api_key.
	headers, err := tokenExtractor("Authorization", "Bearer ", nil)(apiKeyReq(credential.TypeOAuthBearerToken, "at-456"))
	require.NoError(t, err)
	assert.Equal(t, "Bearer at-456", headers["Authorization"])
}

func TestTokenExtractor_CustomHeaderNoPrefix(t *testing.T) {
	// Header names are canonicalized; "X-API-Key" -> "X-Api-Key" (the form the
	// HTTP layer puts on the wire regardless).
	headers, err := tokenExtractor("X-API-Key", "", nil)(apiKeyReq(credential.TypeAPIKey, "raw-key"))
	require.NoError(t, err)
	assert.Equal(t, "raw-key", headers["X-Api-Key"])
	_, hasAuth := headers["Authorization"]
	assert.False(t, hasAuth)
}

func TestTokenExtractor_CaseInsensitiveTokenWins(t *testing.T) {
	// A static header that differs from the token header only in case must not
	// shadow the token: both collapse onto the canonical key and the token wins.
	static := map[string]string{"authorization": "attacker"}
	headers, err := tokenExtractor("Authorization", "Bearer ", static)(apiKeyReq(credential.TypeAPIKey, "real"))
	require.NoError(t, err)
	assert.Len(t, headers, 1)
	assert.Equal(t, "Bearer real", headers["Authorization"])
}

func TestTokenExtractor_PrefixScheme(t *testing.T) {
	headers, err := tokenExtractor("Authorization", "token ", nil)(apiKeyReq(credential.TypeAPIKey, "ghp"))
	require.NoError(t, err)
	assert.Equal(t, "token ghp", headers["Authorization"])
}

func TestTokenExtractor_StaticHeadersMerged(t *testing.T) {
	static := map[string]string{"X-Account-Id": "acme", "X-Api-Version": "2024-01"}
	headers, err := tokenExtractor("X-Auth-Token", "", static)(apiKeyReq(credential.TypeAPIKey, "tok"))
	require.NoError(t, err)
	assert.Equal(t, "tok", headers["X-Auth-Token"])
	assert.Equal(t, "acme", headers["X-Account-Id"])
	assert.Equal(t, "2024-01", headers["X-Api-Version"])
}

func TestTokenExtractor_TokenWinsHeaderCollision(t *testing.T) {
	// A static header that collides with the token header must not shadow the token.
	static := map[string]string{"Authorization": "static-value"}
	headers, err := tokenExtractor("Authorization", "Bearer ", static)(apiKeyReq(credential.TypeAPIKey, "real"))
	require.NoError(t, err)
	assert.Equal(t, "Bearer real", headers["Authorization"])
}

func TestTokenExtractor_DoesNotMutateStatic(t *testing.T) {
	static := map[string]string{"X-A": "1"}
	_, err := tokenExtractor("Authorization", "Bearer ", static)(apiKeyReq(credential.TypeAPIKey, "k"))
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"X-A": "1"}, static, "extractor must not mutate the shared static map")
}

func TestTokenExtractor_Errors(t *testing.T) {
	extract := tokenExtractor("Authorization", "Bearer ", nil)

	_, err := extract(&logical.Request{})
	assert.ErrorContains(t, err, "no credential available")

	_, err = extract(&logical.Request{Credential: &credential.Credential{Type: credential.TypeGitHubToken}})
	assert.ErrorContains(t, err, "unsupported credential type")

	_, err = extract(&logical.Request{Credential: &credential.Credential{
		Type: credential.TypeAPIKey,
		Data: map[string]string{},
	}})
	assert.ErrorContains(t, err, "missing api_key")
}

func TestStatePrefix_AbsentVsPresentEmpty(t *testing.T) {
	// Absent → default "Bearer "
	assert.Equal(t, "Bearer ", statePrefix(map[string]any{}))
	// Present empty → raw (no prefix). This is what enables a raw Authorization header.
	assert.Equal(t, "", statePrefix(map[string]any{"token_prefix": ""}))
	// Present non-empty → verbatim
	assert.Equal(t, "SSWS ", statePrefix(map[string]any{"token_prefix": "SSWS "}))
}

func TestStateString_Default(t *testing.T) {
	assert.Equal(t, "Authorization", stateString(map[string]any{}, "token_header", "Authorization"))
	assert.Equal(t, "Authorization", stateString(map[string]any{"token_header": ""}, "token_header", "Authorization"))
	assert.Equal(t, "X-API-Key", stateString(map[string]any{"token_header": "X-API-Key"}, "token_header", "Authorization"))
}

func TestCoerceStringMap(t *testing.T) {
	assert.Equal(t, map[string]string{"a": "b"}, coerceStringMap(map[string]string{"a": "b"}))
	// JSON round-trip shape
	assert.Equal(t, map[string]string{"a": "b"}, coerceStringMap(map[string]any{"a": "b"}))
	// non-string values in a map[string]any are dropped
	assert.Equal(t, map[string]string{"a": "b"}, coerceStringMap(map[string]any{"a": "b", "n": 5}))
	assert.Nil(t, coerceStringMap(nil))
	assert.Nil(t, coerceStringMap("not-a-map"))
}

func TestResolveUpstream_BuildsExtractorFromState(t *testing.T) {
	// Custom header, raw prefix, plus a static header — all sourced from state.
	state := map[string]any{
		"token_header": "X-Algolia-API-Key",
		"token_prefix": "",
		"headers":      map[string]string{"X-Algolia-Application-Id": "APP123"},
	}
	d, ok := Spec.ResolveUpstream(nil, "", state)
	require.True(t, ok)
	require.NotNil(t, d.ExtractCredentials)

	headers, err := d.ExtractCredentials(apiKeyReq(credential.TypeAPIKey, "algkey"))
	require.NoError(t, err)
	assert.Equal(t, "algkey", headers["X-Algolia-Api-Key"])
	assert.Equal(t, "APP123", headers["X-Algolia-Application-Id"])
}

// TestHeaderApplication_TokenWinsCaseCollision drives the extractor output
// through the same Header.Set application the gateway performs (gateway.go
// prepareHeaders), reproducing the case-collision seam: a static header that
// differs from the token header only in case must not overwrite the token,
// deterministically, regardless of map-iteration order.
func TestHeaderApplication_TokenWinsCaseCollision(t *testing.T) {
	state := map[string]any{
		"token_header": "Authorization",
		"token_prefix": "Bearer ",
		"headers":      map[string]string{"authorization": "attacker", "x-tenant": "acme"},
	}
	// Map iteration is randomized; the applied result must be stable across runs.
	for i := 0; i < 50; i++ {
		d, ok := Spec.ResolveUpstream(nil, "", state)
		require.True(t, ok)
		extracted, err := d.ExtractCredentials(apiKeyReq(credential.TypeAPIKey, "real-token"))
		require.NoError(t, err)

		h := http.Header{}
		for k, v := range extracted {
			h.Set(k, v)
		}
		assert.Equal(t, "Bearer real-token", h.Get("Authorization"))
		assert.Equal(t, "acme", h.Get("X-Tenant"))
	}
}

func TestResolveUpstream_DefaultsWhenStateEmpty(t *testing.T) {
	d, ok := Spec.ResolveUpstream(nil, "", map[string]any{})
	require.True(t, ok)
	headers, err := d.ExtractCredentials(apiKeyReq(credential.TypeAPIKey, "k"))
	require.NoError(t, err)
	assert.Equal(t, "Bearer k", headers["Authorization"])
}

func fieldData(raw map[string]any) *framework.FieldData {
	return &framework.FieldData{Raw: raw, Schema: Spec.ExtraConfigFields}
}

func TestOnConfigWrite_StoresFields(t *testing.T) {
	state, err := Spec.OnConfigWrite(fieldData(map[string]any{
		"token_header": "X-API-Key",
		"token_prefix": "",
		"headers":      map[string]string{"X-Env": "dev"},
	}), map[string]any{})
	require.NoError(t, err)
	assert.Equal(t, "X-API-Key", state["token_header"])
	assert.Equal(t, "", state["token_prefix"])
	assert.Equal(t, map[string]string{"X-Env": "dev"}, stateHeaders(state))
}

func TestOnConfigWrite_PartialPreservesPriorValues(t *testing.T) {
	state := map[string]any{"token_header": "X-API-Key", "token_prefix": ""}
	// A write that only changes headers must not clobber token_header/token_prefix.
	state, err := Spec.OnConfigWrite(fieldData(map[string]any{
		"headers": map[string]string{"X-A": "1"},
	}), state)
	require.NoError(t, err)
	assert.Equal(t, "X-API-Key", state["token_header"])
	assert.Equal(t, "", state["token_prefix"])
	assert.Equal(t, map[string]string{"X-A": "1"}, stateHeaders(state))
}

func TestOnConfigWrite_RejectsInvalidConfig(t *testing.T) {
	_, err := Spec.OnConfigWrite(fieldData(map[string]any{"token_header": "Bad Header"}), map[string]any{})
	assert.ErrorContains(t, err, "invalid token_header")

	_, err = Spec.OnConfigWrite(fieldData(map[string]any{
		"headers": map[string]string{"X-Bad": "line1\nline2"},
	}), map[string]any{})
	assert.ErrorContains(t, err, "invalid value for header")

	_, err = Spec.OnConfigWrite(fieldData(map[string]any{
		"headers": map[string]string{"Bad Key": "v"},
	}), map[string]any{})
	assert.ErrorContains(t, err, "invalid header name")
}

func TestValidateExtraConfig_AllowsEmptyTokenHeader(t *testing.T) {
	// An explicit empty token_header is allowed; it falls back to Authorization.
	assert.NoError(t, Spec.ValidateExtraConfig(map[string]any{"token_header": ""}))
	assert.Error(t, Spec.ValidateExtraConfig(map[string]any{"token_header": "X Y"}))
}

// TestConfigRoundTrip_PersistReload reproduces the SDK persist→reload cycle:
// OnConfigWrite → OnConfigRead (persisted) → JSON storage round-trip →
// OnInitialize. It guards F2 (headers map must survive the JSON round-trip)
// and F3 (an explicit empty token_prefix must survive as a raw header).
func TestConfigRoundTrip_PersistReload(t *testing.T) {
	state, err := Spec.OnConfigWrite(fieldData(map[string]any{
		"token_header": "X-Auth-Token",
		"token_prefix": "",
		"headers":      map[string]string{"X-Account-Id": "acme", "X-Api-Version": "2024-01"},
	}), map[string]any{})
	require.NoError(t, err)

	// What the SDK persists for the extra fields.
	persisted := Spec.OnConfigRead(state)

	// Simulate storage: JSON encode then decode into the generic map shape that
	// Initialize hands to OnInitialize (objects decode to map[string]interface{}).
	blob, err := json.Marshal(persisted)
	require.NoError(t, err)
	var reloaded map[string]any
	require.NoError(t, json.Unmarshal(blob, &reloaded))

	newState := Spec.OnInitialize(reloaded, map[string]any{})

	// Headers survived the round-trip (F2).
	assert.Equal(t, map[string]string{"X-Account-Id": "acme", "X-Api-Version": "2024-01"}, stateHeaders(newState))
	// Raw token (empty prefix) survived (F3).
	assert.Equal(t, "", statePrefix(newState))
	assert.Equal(t, "X-Auth-Token", stateString(newState, "token_header", defaultTokenHeader))

	// And the rebuilt extractor injects the right headers.
	d, ok := Spec.ResolveUpstream(nil, "", newState)
	require.True(t, ok)
	headers, err := d.ExtractCredentials(apiKeyReq(credential.TypeAPIKey, "tok"))
	require.NoError(t, err)
	assert.Equal(t, "tok", headers["X-Auth-Token"])
	assert.Equal(t, "acme", headers["X-Account-Id"])
}

func TestOnInitialize_DefaultsPrefixWhenAbsent(t *testing.T) {
	// A persisted config without token_prefix falls back to the Bearer default.
	newState := Spec.OnInitialize(map[string]any{"token_header": "Authorization"}, map[string]any{})
	assert.Equal(t, "Bearer ", statePrefix(newState))
}

func TestSpec(t *testing.T) {
	assert.Equal(t, "rest", Spec.Name)
	assert.Equal(t, "base_url", Spec.URLConfigKey)
	assert.Equal(t, "", Spec.DefaultURL)
	assert.NotNil(t, Spec.ResolveUpstream)
	assert.NotNil(t, Spec.ExtractCredentials)
	assert.NotNil(t, Factory)
}
