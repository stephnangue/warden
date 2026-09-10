// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package jwt

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetClaim_LiteralTopLevelKey(t *testing.T) {
	claims := map[string]interface{}{"team": "platform-core"}
	assert.Equal(t, "platform-core", getClaim(claims, "team"))
}

func TestGetClaim_NestedJSONPointer(t *testing.T) {
	claims := map[string]interface{}{
		"resource_access": map[string]interface{}{
			"warden": map[string]interface{}{"env": "prod"},
		},
	}
	assert.Equal(t, "prod", getClaim(claims, "/resource_access/warden/env"))
}

func TestGetClaim_NamespacedLiteralKey(t *testing.T) {
	// A namespaced OIDC key contains slashes but has no leading "/", so it is
	// resolved as a literal top-level key, not a JSON Pointer.
	claims := map[string]interface{}{"https://warden.io/env": "prod"}
	assert.Equal(t, "prod", getClaim(claims, "https://warden.io/env"))
}

func TestGetClaim_UnresolvedPointerFailsClosed(t *testing.T) {
	claims := map[string]interface{}{"resource_access": map[string]interface{}{}}
	assert.Nil(t, getClaim(claims, "/resource_access/warden/env"))
	assert.Nil(t, getClaim(claims, "/missing"))
}

func TestGetClaim_EarlyLeafFailsClosed(t *testing.T) {
	// "env" is a string, so walking further into it must not panic and must
	// return nil rather than a partial value.
	claims := map[string]interface{}{"env": "prod"}
	assert.Nil(t, getClaim(claims, "/env/deeper"))
}

func TestGetClaim_FloatCoercedToJSONNumber(t *testing.T) {
	claims := map[string]interface{}{"level": float64(42)}
	assert.Equal(t, json.Number("42"), getClaim(claims, "level"))
}

func TestExtractMetadata_MapsConfiguredClaims(t *testing.T) {
	claims := map[string]interface{}{
		"team": "platform-core",
		"resource_access": map[string]interface{}{
			"warden": map[string]interface{}{"env": "prod"},
		},
	}
	md, err := extractMetadata(claims, map[string]string{
		"team":                        "team",
		"/resource_access/warden/env": "env",
	})
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"team": "platform-core", "env": "prod"}, md)
}

func TestExtractMetadata_NoMappingsReturnsNil(t *testing.T) {
	md, err := extractMetadata(map[string]interface{}{"team": "x"}, nil)
	require.NoError(t, err)
	assert.Nil(t, md)
}

func TestExtractMetadata_AbsentClaimSkipped(t *testing.T) {
	md, err := extractMetadata(map[string]interface{}{"team": "platform"}, map[string]string{
		"team": "team",
		"env":  "env", // not present in claims
	})
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"team": "platform"}, md)
}

func TestExtractMetadata_AllClaimsAbsentReturnsNil(t *testing.T) {
	md, err := extractMetadata(map[string]interface{}{}, map[string]string{"env": "env"})
	require.NoError(t, err)
	assert.Nil(t, md)
}

func TestExtractMetadata_NonStringClaimErrors(t *testing.T) {
	claims := map[string]interface{}{"roles": []interface{}{"a", "b"}}
	md, err := extractMetadata(claims, map[string]string{"roles": "roles"})
	require.Error(t, err)
	assert.Nil(t, md)
}

// TestExtractMetadata_ActSubConsentBinding pins the claim mapping the
// agent-user binding rests on. RFC 8693 §4.1 defines `act` as "agent A acting
// for user B", so on a USER token act.sub names the agent — mapping it to a
// metadata key is what lets a policy compare it to agent.principal.
//
// This is deliberately specific rather than folded into the generic JSON
// Pointer tests: /act/sub is the one mapping the consent check cannot work
// without, and it is otherwise only exercised end-to-end.
func TestExtractMetadata_ActSubConsentBinding(t *testing.T) {
	mapping := map[string]string{"/act/sub": "acting_agent", "team": "team"}

	t.Run("maps the acting agent", func(t *testing.T) {
		md, err := extractMetadata(map[string]interface{}{
			"sub":  "user-8f21c3",
			"team": "platform",
			"act":  map[string]interface{}{"sub": "agent-gateway"},
		}, mapping)
		require.NoError(t, err)
		assert.Equal(t, "agent-gateway", md["acting_agent"])
		assert.Equal(t, "platform", md["team"])
	})

	t.Run("takes the outermost actor of a delegation chain", func(t *testing.T) {
		// /act/sub is the immediate actor, matching actors[0] from
		// extractActChain — the party acting directly for the user.
		md, err := extractMetadata(map[string]interface{}{
			"sub": "user-8f21c3",
			"act": map[string]interface{}{
				"sub": "broker-beta",
				"act": map[string]interface{}{"sub": "agent-gateway"},
			},
		}, mapping)
		require.NoError(t, err)
		assert.Equal(t, "broker-beta", md["acting_agent"])
	})

	t.Run("absent act leaves the key unset so the binding fails closed", func(t *testing.T) {
		// A user token minted without consent carries no `act`. The claim is
		// skipped rather than erroring, so the key is simply missing and the
		// policy condition denies on a no-such-key rather than passing.
		md, err := extractMetadata(map[string]interface{}{
			"sub": "user-8f21c3", "team": "platform",
		}, mapping)
		require.NoError(t, err)
		assert.NotContains(t, md, "acting_agent")
	})

	t.Run("malformed act is rejected, not coerced", func(t *testing.T) {
		_, err := extractMetadata(map[string]interface{}{
			"act": map[string]interface{}{"sub": 42},
		}, mapping)
		assert.Error(t, err, "a non-string act.sub must not be flattened into metadata")
	})
}
