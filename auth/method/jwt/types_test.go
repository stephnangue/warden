package jwt

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

// =============================================================================
// mapToJWTAuthConfig Tests
// =============================================================================

func TestMapToJWTAuthConfig_TTLTypes(t *testing.T) {
	t.Run("string ttl", func(t *testing.T) {
		config, err := mapToJWTAuthConfig(map[string]any{"token_ttl": "2h"})
		require.NoError(t, err)
		assert.Equal(t, 2*time.Hour, config.TokenTTL)
	})

	t.Run("int ttl", func(t *testing.T) {
		config, err := mapToJWTAuthConfig(map[string]any{"token_ttl": 3600})
		require.NoError(t, err)
		assert.Equal(t, time.Hour, config.TokenTTL)
	})

	t.Run("float64 ttl", func(t *testing.T) {
		config, err := mapToJWTAuthConfig(map[string]any{"token_ttl": float64(7200)})
		require.NoError(t, err)
		assert.Equal(t, 2*time.Hour, config.TokenTTL)
	})

	t.Run("duration ttl", func(t *testing.T) {
		config, err := mapToJWTAuthConfig(map[string]any{"token_ttl": 30 * time.Minute})
		require.NoError(t, err)
		assert.Equal(t, 30*time.Minute, config.TokenTTL)
	})

	t.Run("defaults", func(t *testing.T) {
		config, err := mapToJWTAuthConfig(map[string]any{})
		require.NoError(t, err)
		assert.Equal(t, time.Hour, config.TokenTTL)
		assert.Equal(t, "sub", config.UserClaim)
	})
}

// =============================================================================
// verifyURLReachable Tests
// =============================================================================
