package helper

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetClaim_LiteralTopLevelKey(t *testing.T) {
	claims := map[string]interface{}{"team": "platform-core"}
	assert.Equal(t, "platform-core", GetClaim(claims, "team"))
}

func TestGetClaim_NestedJSONPointer(t *testing.T) {
	claims := map[string]interface{}{
		"resource_access": map[string]interface{}{
			"warden": map[string]interface{}{"env": "prod"},
		},
	}
	assert.Equal(t, "prod", GetClaim(claims, "/resource_access/warden/env"))
}

func TestGetClaim_NamespacedLiteralKey(t *testing.T) {
	// A namespaced OIDC key contains slashes but has no leading "/", so it is
	// resolved as a literal top-level key, not a JSON Pointer.
	claims := map[string]interface{}{"https://warden.io/env": "prod"}
	assert.Equal(t, "prod", GetClaim(claims, "https://warden.io/env"))
}

func TestGetClaim_UnresolvedPointerFailsClosed(t *testing.T) {
	claims := map[string]interface{}{"resource_access": map[string]interface{}{}}
	assert.Nil(t, GetClaim(claims, "/resource_access/warden/env"))
	assert.Nil(t, GetClaim(claims, "/missing"))
	assert.Nil(t, GetClaim(claims, "missing"))
}

func TestGetClaim_EarlyLeafFailsClosed(t *testing.T) {
	// "env" is a string, so walking further into it must not panic and must
	// return nil rather than a partial value.
	claims := map[string]interface{}{"env": "prod"}
	assert.Nil(t, GetClaim(claims, "/env/deeper"))
}

func TestGetClaim_FloatCoercedToJSONNumber(t *testing.T) {
	claims := map[string]interface{}{
		"level": float64(42),
		"ratio": float64(1.9),
		"neg":   float64(-7.5),
		"f32":   float32(3),
		"deep":  map[string]interface{}{"n": float64(10)},
	}
	assert.Equal(t, json.Number("42"), GetClaim(claims, "level"))
	assert.Equal(t, json.Number("1"), GetClaim(claims, "ratio"), "a fraction is truncated")
	assert.Equal(t, json.Number("-7"), GetClaim(claims, "neg"))
	assert.Equal(t, json.Number("3"), GetClaim(claims, "f32"))
	assert.Equal(t, json.Number("10"), GetClaim(claims, "/deep/n"))
}

func TestGetClaim_NonScalarReturnedAsIs(t *testing.T) {
	groups := []interface{}{"a", "b"}
	claims := map[string]interface{}{"groups": groups, "ok": true}
	assert.Equal(t, groups, GetClaim(claims, "groups"))
	assert.Equal(t, true, GetClaim(claims, "ok"))
	assert.Equal(t, "b", GetClaim(claims, "/groups/1"))
}
