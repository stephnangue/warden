// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package jwt

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// validateBoundClaims Tests
// =============================================================================

func TestValidateBoundClaims_NoBoundClaims(t *testing.T) {
	claims := map[string]interface{}{
		"sub":   "user123",
		"email": "user@example.com",
	}

	err := validateBoundClaims(claims, nil)
	assert.NoError(t, err)
}

func TestValidateBoundClaims_EmptyBoundClaims(t *testing.T) {
	claims := map[string]interface{}{
		"sub": "user123",
	}
	boundClaims := map[string]any{}

	err := validateBoundClaims(claims, boundClaims)
	assert.NoError(t, err)
}

func TestValidateBoundClaims_SingleMatch(t *testing.T) {
	claims := map[string]interface{}{
		"sub": "user123",
		"iss": "https://issuer.example.com",
	}
	boundClaims := map[string]any{
		"iss": "https://issuer.example.com",
	}

	err := validateBoundClaims(claims, boundClaims)
	assert.NoError(t, err)
}

func TestValidateBoundClaims_MultipleMatches(t *testing.T) {
	claims := map[string]interface{}{
		"sub":    "user123",
		"iss":    "https://issuer.example.com",
		"aud":    "my-app",
		"tenant": "acme",
	}
	boundClaims := map[string]any{
		"iss":    "https://issuer.example.com",
		"tenant": "acme",
	}

	err := validateBoundClaims(claims, boundClaims)
	assert.NoError(t, err)
}

func TestValidateBoundClaims_MissingClaim(t *testing.T) {
	claims := map[string]interface{}{
		"sub": "user123",
	}
	boundClaims := map[string]any{
		"tenant": "acme",
	}

	err := validateBoundClaims(claims, boundClaims)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required claim 'tenant' not found")
}

func TestValidateBoundClaims_MismatchedValue(t *testing.T) {
	claims := map[string]interface{}{
		"sub":    "user123",
		"tenant": "other-tenant",
	}
	boundClaims := map[string]any{
		"tenant": "acme",
	}

	err := validateBoundClaims(claims, boundClaims)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "claim 'tenant' does not match")
}

func TestValidateBoundClaims_NumericClaim(t *testing.T) {
	claims := map[string]interface{}{
		"sub":   "user123",
		"level": 5,
	}
	boundClaims := map[string]any{
		"level": 5,
	}

	err := validateBoundClaims(claims, boundClaims)
	assert.NoError(t, err)
}

func TestValidateBoundClaims_BooleanClaim(t *testing.T) {
	claims := map[string]interface{}{
		"sub":     "user123",
		"is_admin": true,
	}
	boundClaims := map[string]any{
		"is_admin": true,
	}

	err := validateBoundClaims(claims, boundClaims)
	assert.NoError(t, err)
}

// =============================================================================
// extractClaim Tests
// =============================================================================

func TestExtractClaim_StringValue(t *testing.T) {
	claims := map[string]interface{}{
		"sub":   "user123",
		"email": "user@example.com",
	}

	result := extractClaim(claims, "sub")
	assert.Equal(t, "user123", result)

	result = extractClaim(claims, "email")
	assert.Equal(t, "user@example.com", result)
}

func TestExtractClaim_MissingClaim(t *testing.T) {
	claims := map[string]interface{}{
		"sub": "user123",
	}

	result := extractClaim(claims, "email")
	assert.Empty(t, result)
}

func TestExtractClaim_NumericValue(t *testing.T) {
	claims := map[string]interface{}{
		"level": 42,
	}

	result := extractClaim(claims, "level")
	assert.Equal(t, "42", result)
}

func TestExtractClaim_FloatValue(t *testing.T) {
	claims := map[string]interface{}{
		"score": 99.5,
	}

	result := extractClaim(claims, "score")
	assert.Equal(t, "99.5", result)
}

func TestExtractClaim_BoolValue(t *testing.T) {
	claims := map[string]interface{}{
		"verified": true,
	}

	result := extractClaim(claims, "verified")
	assert.Equal(t, "true", result)
}

func TestExtractClaim_ArrayValue(t *testing.T) {
	claims := map[string]interface{}{
		"groups": []interface{}{"admin", "users", "developers"},
	}

	result := extractClaim(claims, "groups")
	assert.Equal(t, "admin,users,developers", result)
}

func TestExtractClaim_EmptyArray(t *testing.T) {
	claims := map[string]interface{}{
		"groups": []interface{}{},
	}

	result := extractClaim(claims, "groups")
	assert.Empty(t, result)
}

func TestExtractClaim_MixedArray(t *testing.T) {
	claims := map[string]interface{}{
		"mixed": []interface{}{"string", 42, true},
	}

	result := extractClaim(claims, "mixed")
	assert.Equal(t, "string,42,true", result)
}

func TestExtractClaim_NestedPath(t *testing.T) {
	// Note: current implementation doesn't support nested paths
	// This test documents current behavior
	claims := map[string]interface{}{
		"user": map[string]interface{}{
			"name": "John",
		},
	}

	// Direct access doesn't work for nested
	result := extractClaim(claims, "user.name")
	assert.Empty(t, result)

	// But the whole nested object can be extracted
	result = extractClaim(claims, "user")
	assert.Contains(t, result, "name")
}

// =============================================================================
// buildJWTMetadata Tests
// =============================================================================

func TestBuildJWTMetadata_BasicClaims(t *testing.T) {
	claims := map[string]interface{}{
		"sub":   "user123",
		"iss":   "https://issuer.example.com",
		"email": "user@example.com",
	}
	config := &JWTAuthConfig{
		Mode: "jwt",
	}

	metadata := buildJWTMetadata(claims, config)

	assert.Equal(t, "jwt", metadata["auth_method"])
	assert.Equal(t, "user123", metadata["subject"])
	assert.Equal(t, "https://issuer.example.com", metadata["issuer"])
	assert.Equal(t, "user@example.com", metadata["email"])
}

func TestBuildJWTMetadata_MissingClaims(t *testing.T) {
	claims := map[string]interface{}{
		"sub": "user123",
	}
	config := &JWTAuthConfig{
		Mode: "jwt",
	}

	metadata := buildJWTMetadata(claims, config)

	assert.Equal(t, "jwt", metadata["auth_method"])
	assert.Equal(t, "user123", metadata["subject"])
	_, hasIssuer := metadata["issuer"]
	assert.False(t, hasIssuer)
	_, hasEmail := metadata["email"]
	assert.False(t, hasEmail)
}

func TestBuildJWTMetadata_WithClaimMappings(t *testing.T) {
	claims := map[string]interface{}{
		"sub":             "user123",
		"preferred_name":  "John Doe",
		"department":      "Engineering",
		"employee_id":     "E12345",
	}
	config := &JWTAuthConfig{
		Mode: "jwt",
		ClaimMappings: map[string]string{
			"preferred_name": "display_name",
			"department":     "dept",
			"employee_id":    "emp_id",
		},
	}

	metadata := buildJWTMetadata(claims, config)

	assert.Equal(t, "John Doe", metadata["display_name"])
	assert.Equal(t, "Engineering", metadata["dept"])
	assert.Equal(t, "E12345", metadata["emp_id"])
}

func TestBuildJWTMetadata_WithGroupsClaim(t *testing.T) {
	claims := map[string]interface{}{
		"sub":    "user123",
		"groups": []interface{}{"admin", "developers"},
	}
	config := &JWTAuthConfig{
		Mode:        "jwt",
		GroupsClaim: "groups",
	}

	metadata := buildJWTMetadata(claims, config)

	assert.Equal(t, "admin,developers", metadata["groups"])
}

func TestBuildJWTMetadata_CustomGroupsClaim(t *testing.T) {
	claims := map[string]interface{}{
		"sub":   "user123",
		"roles": []interface{}{"role1", "role2"},
	}
	config := &JWTAuthConfig{
		Mode:        "jwt",
		GroupsClaim: "roles",
	}

	metadata := buildJWTMetadata(claims, config)

	assert.Equal(t, "role1,role2", metadata["groups"])
}

func TestBuildJWTMetadata_EmptyGroupsClaim(t *testing.T) {
	claims := map[string]interface{}{
		"sub":    "user123",
		"groups": []interface{}{},
	}
	config := &JWTAuthConfig{
		Mode:        "jwt",
		GroupsClaim: "groups",
	}

	metadata := buildJWTMetadata(claims, config)

	_, hasGroups := metadata["groups"]
	assert.False(t, hasGroups)
}

func TestBuildJWTMetadata_MissingGroupsClaim(t *testing.T) {
	claims := map[string]interface{}{
		"sub": "user123",
	}
	config := &JWTAuthConfig{
		Mode:        "jwt",
		GroupsClaim: "groups",
	}

	metadata := buildJWTMetadata(claims, config)

	_, hasGroups := metadata["groups"]
	assert.False(t, hasGroups)
}

func TestBuildJWTMetadata_EmptyConfig(t *testing.T) {
	claims := map[string]interface{}{
		"sub": "user123",
	}
	config := &JWTAuthConfig{}

	metadata := buildJWTMetadata(claims, config)

	assert.Equal(t, "jwt", metadata["auth_method"])
	assert.Equal(t, "user123", metadata["subject"])
}

// =============================================================================
// Table-Driven Tests
// =============================================================================

func TestValidateBoundClaims_TableDriven(t *testing.T) {
	tests := []struct {
		name        string
		claims      map[string]interface{}
		boundClaims map[string]any
		expectError bool
		errorMsg    string
	}{
		{
			name:        "No bound claims",
			claims:      map[string]interface{}{"sub": "user"},
			boundClaims: nil,
			expectError: false,
		},
		{
			name:        "Single matching claim",
			claims:      map[string]interface{}{"sub": "user", "iss": "issuer"},
			boundClaims: map[string]any{"iss": "issuer"},
			expectError: false,
		},
		{
			name:        "Missing required claim",
			claims:      map[string]interface{}{"sub": "user"},
			boundClaims: map[string]any{"iss": "issuer"},
			expectError: true,
			errorMsg:    "not found",
		},
		{
			name:        "Mismatched claim value",
			claims:      map[string]interface{}{"sub": "user", "iss": "wrong"},
			boundClaims: map[string]any{"iss": "expected"},
			expectError: true,
			errorMsg:    "does not match",
		},
		{
			name:        "Multiple matching claims",
			claims:      map[string]interface{}{"a": "1", "b": "2", "c": "3"},
			boundClaims: map[string]any{"a": "1", "c": "3"},
			expectError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateBoundClaims(tc.claims, tc.boundClaims)

			if tc.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestExtractClaim_TableDriven(t *testing.T) {
	tests := []struct {
		name      string
		claims    map[string]interface{}
		claimName string
		expected  string
	}{
		{
			name:      "String claim",
			claims:    map[string]interface{}{"sub": "user123"},
			claimName: "sub",
			expected:  "user123",
		},
		{
			name:      "Missing claim",
			claims:    map[string]interface{}{"sub": "user123"},
			claimName: "email",
			expected:  "",
		},
		{
			name:      "Integer claim",
			claims:    map[string]interface{}{"level": 5},
			claimName: "level",
			expected:  "5",
		},
		{
			name:      "Boolean true",
			claims:    map[string]interface{}{"active": true},
			claimName: "active",
			expected:  "true",
		},
		{
			name:      "Boolean false",
			claims:    map[string]interface{}{"active": false},
			claimName: "active",
			expected:  "false",
		},
		{
			name:      "Array claim",
			claims:    map[string]interface{}{"roles": []interface{}{"a", "b"}},
			claimName: "roles",
			expected:  "a,b",
		},
		{
			name:      "Empty string",
			claims:    map[string]interface{}{"name": ""},
			claimName: "name",
			expected:  "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := extractClaim(tc.claims, tc.claimName)
			assert.Equal(t, tc.expected, result)
		})
	}
}
