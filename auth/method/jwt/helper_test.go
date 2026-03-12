// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package jwt

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/auth/helper"
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
	assert.Contains(t, err.Error(), "not found")
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
	assert.Contains(t, err.Error(), "mismatch")
}

func TestValidateBoundClaims_NumericClaim(t *testing.T) {
	claims := map[string]interface{}{
		"sub":   "user123",
		"level": float64(5), // JSON numbers decode as float64
	}
	boundClaims := map[string]any{
		"level": float64(5),
	}

	err := validateBoundClaims(claims, boundClaims)
	assert.NoError(t, err)
}

func TestValidateBoundClaims_BooleanClaim(t *testing.T) {
	claims := map[string]interface{}{
		"sub":      "user123",
		"is_admin": true,
	}
	boundClaims := map[string]any{
		"is_admin": true,
	}

	err := validateBoundClaims(claims, boundClaims)
	assert.NoError(t, err)
}

// =============================================================================
// claimValuesEqual Type Safety Tests (Phase 4: M1)
// =============================================================================

func TestClaimValuesEqual_TypeSafety(t *testing.T) {
	tests := []struct {
		name     string
		actual   interface{}
		expected interface{}
		want     bool
	}{
		// Same-type matches
		{"string match", "hello", "hello", true},
		{"string mismatch", "hello", "world", false},
		{"float64 match", float64(42), float64(42), true},
		{"float64 mismatch", float64(42), float64(99), false},
		{"int match", 5, 5, true},
		{"int mismatch", 5, 6, false},
		{"bool true match", true, true, true},
		{"bool false match", false, false, true},
		{"bool mismatch", true, false, false},

		// Cross-type numeric (allowed: JSON numbers are float64)
		{"float64 actual vs int expected", float64(5), 5, true},
		{"int actual vs float64 expected", 5, float64(5), true},
		{"int64 actual vs float64 expected", int64(5), float64(5), true},

		// Cross-type rejection (no coercion between unrelated types)
		{"int vs string rejected", 1, "1", false},
		{"string vs int rejected", "1", 1, false},
		{"bool vs string rejected", true, "true", false},
		{"string vs bool rejected", "true", true, false},
		{"float vs string rejected", float64(1.0), "1", false},
		{"string vs float rejected", "1", float64(1.0), false},
		{"bool vs int rejected", true, 1, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := claimValuesEqual(tc.actual, tc.expected)
			assert.Equal(t, tc.want, got, "claimValuesEqual(%v [%T], %v [%T])", tc.actual, tc.actual, tc.expected, tc.expected)
		})
	}
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
// parseNumericClaim Tests
// =============================================================================

func TestParseNumericClaim(t *testing.T) {
	tests := []struct {
		name     string
		value    any
		wantVal  int64
		wantOk   bool
	}{
		{"float64", float64(1234567890), 1234567890, true},
		{"int64", int64(1234567890), 1234567890, true},
		{"int", int(1234567890), 1234567890, true},
		{"float64 with fraction (truncates)", float64(1234567890.5), 1234567890, true},
		{"string rejected", "1234567890", 0, false},
		{"bool rejected", true, 0, false},
		{"nil rejected", nil, 0, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			val, ok := parseNumericClaim(tc.value)
			assert.Equal(t, tc.wantOk, ok)
			if ok {
				assert.Equal(t, tc.wantVal, val)
			}
		})
	}
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
			errorMsg:    "mismatch",
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

// =============================================================================
// validateBoundURIPatterns Tests (via helper.MatchAny)
// =============================================================================

func TestBoundURIPatterns_Validation(t *testing.T) {
	tests := []struct {
		name       string
		claimValue string
		patterns   []string
		wantMatch  bool
	}{
		// SPIFFE ID patterns
		{"exact spiffe match", "spiffe://example.com/dept/svc", []string{"spiffe://example.com/dept/svc"}, true},
		{"plus trust domain", "spiffe://example.com/dept/svc", []string{"spiffe://+/dept/svc"}, true},
		{"prefix wildcard", "spiffe://example.com/dept/team/svc", []string{"spiffe://example.com/dept/*"}, true},
		{"scheme catch-all", "spiffe://anything/any/path", []string{"spiffe://*"}, true},
		{"combined plus and star", "spiffe://example.com/dept/team/svc", []string{"spiffe://+/dept/*"}, true},
		{"mismatch domain", "spiffe://other.com/dept/svc", []string{"spiffe://example.com/dept/svc"}, false},
		{"mismatch path", "spiffe://example.com/other/svc", []string{"spiffe://+/dept/svc"}, false},
		{"wrong scheme", "https://example.com/path", []string{"spiffe://*"}, false},

		// Multiple patterns (OR semantics)
		{"matches second pattern", "spiffe://other.com/web", []string{"spiffe://example.com/web", "spiffe://other.com/web"}, true},
		{"matches none", "spiffe://third.com/web", []string{"spiffe://example.com/web", "spiffe://other.com/web"}, false},

		// Empty claim
		{"empty claim value", "", []string{"spiffe://*"}, false},
		{"empty patterns", "spiffe://example.com/svc", []string{}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claims := map[string]interface{}{
				"sub": tc.claimValue,
			}

			claimValue := extractClaim(claims, "sub")
			var matched bool
			if claimValue != "" && len(tc.patterns) > 0 {
				matched = helper.MatchAny(claimValue, tc.patterns)
			}

			if tc.wantMatch {
				assert.True(t, matched, "expected claim %q to match patterns %v", tc.claimValue, tc.patterns)
			} else {
				assert.False(t, matched, "expected claim %q NOT to match patterns %v", tc.claimValue, tc.patterns)
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
