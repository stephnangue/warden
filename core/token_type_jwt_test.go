package core

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Sample JWTs for testing (these are not valid signatures, just format tests)
const (
	// A typical JWT format: header.payload.signature
	sampleJWT = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.POstGetfAytaZS82wHcjoTyoqhMyxXiWdR7Nn7A29DNSl0EiXLdwJ6xC6AfgZWF1bOsS_TuYI3OG85AmiExREkrS6tDfTQ2B3WXlrr-wp5AokiRbz3_oB4OxG-W9KcEEbDRcZc0nH3L7LzYptiy1PtAylQGxHTWZXtGz4ht0bAecBgmpdgXMguEIcoqPJ1n3pIWk_dUZegpqx0Lka21H6XxUTxiy8OcaarA8zdnPUnV6AmNP3ecFawIFYdvJB_cm-GvpCSbr8G8y_Mllj8f4x9nBH8pQux89_6gUY618iYv7tuPWBFfEbLxtF2pZS6YC1aSfLQxeNe8djT9YjpvRZA"
	// Another valid JWT format
	shortJWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
)

func TestJWTRoleTokenType_Metadata(t *testing.T) {
	jwtType := &JWTRoleTokenType{}
	meta := jwtType.Metadata()

	assert.Equal(t, "jwt_role", meta.Name)
	assert.Equal(t, "jwtr_", meta.IDPrefix)
	assert.Equal(t, "eyJ", meta.ValuePrefix)
	assert.Equal(t, "JWT bearer token with role binding", meta.Description)
	assert.Equal(t, 1*time.Hour, meta.DefaultTTL)
}

func TestJWTRoleTokenType_ValidateValue(t *testing.T) {
	jwtType := &JWTRoleTokenType{}

	tests := []struct {
		name     string
		token    string
		expected bool
	}{
		{
			name:     "valid JWT format",
			token:    sampleJWT,
			expected: true,
		},
		{
			name:     "valid short JWT",
			token:    shortJWT,
			expected: true,
		},
		{
			name:     "missing signature part",
			token:    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0",
			expected: false,
		},
		{
			name:     "only header",
			token:    "eyJhbGciOiJIUzI1NiJ9",
			expected: false,
		},
		{
			name:     "not a JWT - warden token",
			token:    "cws.abc123def456",
			expected: false,
		},
		{
			name:     "not a JWT - random string",
			token:    "not-a-jwt-token",
			expected: false,
		},
		{
			name:     "empty string",
			token:    "",
			expected: false,
		},
		{
			name:     "JWT with empty parts",
			token:    "eyJ..signature",
			expected: false,
		},
		{
			name:     "four parts instead of three",
			token:    "eyJhbGciOiJIUzI1NiJ9.part2.part3.part4",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := jwtType.ValidateValue(tt.token)
			assert.Equal(t, tt.expected, result, "token: %s", tt.token)
		})
	}
}

func TestJWTRoleTokenType_ComputeID(t *testing.T) {
	jwtType := &JWTRoleTokenType{}

	// Test that ComputeID produces a deterministic ID
	id1 := jwtType.ComputeID(sampleJWT)
	id2 := jwtType.ComputeID(sampleJWT)

	assert.Equal(t, id1, id2, "ComputeID should be deterministic")
	assert.True(t, strings.HasPrefix(id1, "jwtr_"), "ID should have jwtr_ prefix")
	assert.Len(t, id1, 37, "ID should be jwtr_ (5 chars) + 32 char hash")

	// Different JWTs should produce different IDs
	id3 := jwtType.ComputeID(shortJWT)
	assert.NotEqual(t, id1, id3, "Different JWTs should have different IDs")
	assert.True(t, strings.HasPrefix(id3, "jwtr_"), "ID should have jwtr_ prefix")
}

func TestJWTRoleTokenType_LookupKey(t *testing.T) {
	jwtType := &JWTRoleTokenType{}
	assert.Equal(t, "jwt", jwtType.LookupKey())
}

func TestJWTRoleTokenType_Generate(t *testing.T) {
	jwtType := &JWTRoleTokenType{}

	t.Run("nil authData returns unchanged entry", func(t *testing.T) {
		entry := &TokenEntry{
			Data: map[string]string{},
		}

		result, err := jwtType.Generate(nil, entry)
		require.NoError(t, err)
		assert.Empty(t, result["jwt"])
	})

	t.Run("empty TokenValue returns unchanged entry", func(t *testing.T) {
		entry := &TokenEntry{
			Data: map[string]string{},
		}

		authData := &AuthData{TokenValue: "", RoleName: "terraform"}
		result, err := jwtType.Generate(authData, entry)
		require.NoError(t, err)
		assert.Empty(t, result["jwt"])
	})

	t.Run("with JWT and empty role", func(t *testing.T) {
		entry := &TokenEntry{
			Data: map[string]string{},
		}

		authData := &AuthData{TokenValue: sampleJWT, RoleName: ""}
		result, err := jwtType.Generate(authData, entry)
		require.NoError(t, err)
		// JWT should be stored as hash (not raw value) for security
		expectedHash := sha256.Sum256([]byte(sampleJWT))
		assert.Equal(t, hex.EncodeToString(expectedHash[:]), result["jwt"])
	})

	t.Run("with JWT and role", func(t *testing.T) {
		entry := &TokenEntry{
			Data: map[string]string{},
		}

		authData := &AuthData{TokenValue: sampleJWT, RoleName: "terraform"}
		result, err := jwtType.Generate(authData, entry)
		require.NoError(t, err)
		// JWT+role composite should be stored as hash for security
		expectedHash := sha256.Sum256([]byte(sampleJWT + ":terraform"))
		assert.Equal(t, hex.EncodeToString(expectedHash[:]), result["jwt"])
	})
}

func TestJWTRoleTokenType_ComputeData(t *testing.T) {
	jwtType := &JWTRoleTokenType{}

	t.Run("same JWT different roles produce different hashes", func(t *testing.T) {
		hash1 := jwtType.ComputeData(sampleJWT, "role1")
		hash2 := jwtType.ComputeData(sampleJWT, "role2")

		assert.NotEqual(t, hash1, hash2, "Same JWT with different roles should have different hashes")
	})

	t.Run("same JWT same role produces same hash", func(t *testing.T) {
		hash1 := jwtType.ComputeData(sampleJWT, "terraform")
		hash2 := jwtType.ComputeData(sampleJWT, "terraform")

		assert.Equal(t, hash1, hash2, "Same JWT with same role should have same hash")
	})

	t.Run("empty role uses JWT only", func(t *testing.T) {
		hashWithEmptyRole := jwtType.ComputeData(sampleJWT, "")
		expectedHash := sha256.Sum256([]byte(sampleJWT))

		assert.Equal(t, hex.EncodeToString(expectedHash[:]), hashWithEmptyRole)
	})

	t.Run("hash and ComputeID produce consistent token IDs", func(t *testing.T) {
		// Simulate the token creation flow
		entry := &TokenEntry{
			Data: map[string]string{},
		}
		authData := &AuthData{TokenValue: sampleJWT, RoleName: "myapp"}
		jwtType.Generate(authData, entry)

		// The stored hash should match ComputeData
		expectedHash := jwtType.ComputeData(sampleJWT, "myapp")
		assert.Equal(t, expectedHash, entry.Data["jwt"])

		// Token ID is computed from the hash
		tokenID := jwtType.ComputeID(entry.Data["jwt"])

		// Lookup should compute the same ID: hash first, then ComputeID
		lookupHash := jwtType.ComputeData(sampleJWT, "myapp")
		lookupID := jwtType.ComputeID(lookupHash)

		assert.Equal(t, tokenID, lookupID, "Token creation and lookup should produce same ID")
		assert.True(t, strings.HasPrefix(tokenID, "jwtr_"))
	})
}

func TestJWTRoleTokenType_RegisteredInRegistry(t *testing.T) {
	registry := NewTokenTypeRegistry()

	// Register JWT type
	err := registry.Register(&JWTRoleTokenType{})
	require.NoError(t, err)

	// Should be able to retrieve by name
	tokenType, err := registry.GetByName("jwt_role")
	require.NoError(t, err)
	assert.Equal(t, "jwt_role", tokenType.Metadata().Name)

	// Should detect JWT by prefix
	detectedType, err := registry.DetectType(sampleJWT)
	require.NoError(t, err)
	assert.Equal(t, "jwt_role", detectedType.Metadata().Name)

	// Should not detect non-JWT tokens as JWT
	_, err = registry.DetectType("cws.not-a-jwt")
	assert.Error(t, err) // Should fail because cws. is a different prefix
}
