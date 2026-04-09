package jwt

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestJWTRole_ParseTokenTTL(t *testing.T) {
	t.Run("empty returns 1h", func(t *testing.T) {
		r := &JWTRole{}
		d, err := r.ParseTokenTTL()
		require.NoError(t, err)
		assert.Equal(t, time.Hour, d)
	})

	t.Run("valid string", func(t *testing.T) {
		r := &JWTRole{TokenTTL: "30m"}
		d, err := r.ParseTokenTTL()
		require.NoError(t, err)
		assert.Equal(t, 30*time.Minute, d)
	})

	t.Run("invalid", func(t *testing.T) {
		r := &JWTRole{TokenTTL: "bad"}
		_, err := r.ParseTokenTTL()
		assert.Error(t, err)
	})
}

func TestJWTRole_ParseMaxAge(t *testing.T) {
	t.Run("empty returns 0", func(t *testing.T) {
		r := &JWTRole{}
		d, err := r.ParseMaxAge()
		require.NoError(t, err)
		assert.Equal(t, time.Duration(0), d)
	})

	t.Run("valid", func(t *testing.T) {
		r := &JWTRole{MaxAge: "15m"}
		d, err := r.ParseMaxAge()
		require.NoError(t, err)
		assert.Equal(t, 15*time.Minute, d)
	})

	t.Run("invalid", func(t *testing.T) {
		r := &JWTRole{MaxAge: "bad"}
		_, err := r.ParseMaxAge()
		assert.Error(t, err)
	})
}

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
