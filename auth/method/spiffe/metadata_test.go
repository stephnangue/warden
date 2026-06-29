package spiffe

import (
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractSPIFFEIDMetadata(t *testing.T) {
	id, err := spiffeid.FromString("spiffe://example.org/ns/prod/sa/ci")
	require.NoError(t, err)

	t.Run("maps components", func(t *testing.T) {
		// mappings are source (SPIFFE-ID component) -> target (metadata key)
		md := extractSPIFFEIDMetadata(map[string]string{
			"trust_domain": "td",
			"spiffe_id":    "id",
			"path":         "path",
		}, id)
		assert.Equal(t, map[string]string{
			"td":   "example.org",
			"id":   "spiffe://example.org/ns/prod/sa/ci",
			"path": "/ns/prod/sa/ci",
		}, md)
	})

	t.Run("nil mappings", func(t *testing.T) {
		assert.Nil(t, extractSPIFFEIDMetadata(nil, id))
	})

	t.Run("unknown selector skipped -> nil", func(t *testing.T) {
		assert.Nil(t, extractSPIFFEIDMetadata(map[string]string{"nope": "x"}, id))
	})
}

func TestSpiffe_ExtractMetadata_Claims(t *testing.T) {
	claims := map[string]interface{}{
		"team": "platform-core",
		"resource_access": map[string]interface{}{
			"warden": map[string]interface{}{"env": "prod"},
		},
		"roles": []interface{}{"a", "b"},
	}

	t.Run("literal and nested pointer", func(t *testing.T) {
		md, err := extractMetadata(claims, map[string]string{
			"team":                        "team",
			"/resource_access/warden/env": "env",
		})
		require.NoError(t, err)
		assert.Equal(t, map[string]string{"team": "platform-core", "env": "prod"}, md)
	})

	t.Run("non-string claim errors", func(t *testing.T) {
		_, err := extractMetadata(claims, map[string]string{"roles": "r"})
		require.Error(t, err)
	})

	t.Run("nil mappings", func(t *testing.T) {
		md, err := extractMetadata(claims, nil)
		require.NoError(t, err)
		assert.Nil(t, md)
	})
}

func TestMergeStringMaps(t *testing.T) {
	assert.Nil(t, mergeStringMaps(nil, nil))
	assert.Equal(t, map[string]string{"a": "1"}, mergeStringMaps(map[string]string{"a": "1"}, nil))
	// b wins on conflict.
	assert.Equal(t, map[string]string{"a": "2", "b": "3"},
		mergeStringMaps(map[string]string{"a": "1"}, map[string]string{"a": "2", "b": "3"}))
}

func TestRole_MetadataMappings_RoundTripAndValidation(t *testing.T) {
	b, ctx := createTestBackend(t)

	t.Run("round-trip", func(t *testing.T) {
		resp := createRole(t, b, ctx, map[string]any{
			"name":            "meta",
			"trust_domain":    "example.org",
			"bound_audiences": "warden",
			"metadata_mappings": map[string]any{
				"trust_domain": "td",
			},
			"metadata_claims": map[string]any{
				"/resource_access/warden/env": "env",
			},
		})
		require.Nil(t, resp.Err)

		role, err := b.getRole(ctx, "meta")
		require.NoError(t, err)
		assert.Equal(t, map[string]string{"trust_domain": "td"}, role.MetadataMappings)
		assert.Equal(t, map[string]string{"/resource_access/warden/env": "env"}, role.MetadataClaims)
	})

	t.Run("invalid metadata_mappings field rejected", func(t *testing.T) {
		resp := createRole(t, b, ctx, map[string]any{
			"name":              "bad-meta",
			"trust_domain":      "example.org",
			"metadata_mappings": map[string]any{"not_a_component": "x"},
		})
		require.NotNil(t, resp.Err)
		assert.Contains(t, resp.Err.Error(), "invalid metadata_mappings field")
	})
}
