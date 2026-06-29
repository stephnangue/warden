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
