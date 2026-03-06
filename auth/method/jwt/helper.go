package jwt

import (
	"fmt"
	"strings"
)

// errAuthFailed is a generic error returned for all authentication failures
// to prevent information leakage about which specific check failed.
var errAuthFailed = fmt.Errorf("authentication failed")

// validateBoundClaims validates that JWT claims match the bound claims.
// Returns a descriptive error for server-side logging; callers should return
// errAuthFailed to clients instead.
func validateBoundClaims(claims map[string]interface{}, boundClaims map[string]any) error {
	for key, expectedValue := range boundClaims {
		actualValue, exists := claims[key]
		if !exists {
			return fmt.Errorf("required claim %q not found in JWT", key)
		}

		if !claimValuesEqual(actualValue, expectedValue) {
			return fmt.Errorf("claim %q value mismatch", key)
		}
	}
	return nil
}

// claimValuesEqual performs type-aware comparison of claim values.
// Values must be the same type and equal. No cross-type coercion is allowed
// (e.g., int 1 does NOT match string "1").
func claimValuesEqual(actual, expected interface{}) bool {
	switch e := expected.(type) {
	case string:
		a, ok := actual.(string)
		return ok && a == e
	case float64:
		// JSON numbers decode as float64
		switch a := actual.(type) {
		case float64:
			return a == e
		case int:
			return float64(a) == e
		case int64:
			return float64(a) == e
		default:
			return false
		}
	case int:
		switch a := actual.(type) {
		case int:
			return a == e
		case int64:
			return a == int64(e)
		case float64:
			return a == float64(e)
		default:
			return false
		}
	case bool:
		a, ok := actual.(bool)
		return ok && a == e
	default:
		// Reject unknown types — no implicit coercion
		return false
	}
}

// buildJWTMetadata extracts metadata from JWT claims
func buildJWTMetadata(claims map[string]interface{}, config *JWTAuthConfig) map[string]string {
	metadata := map[string]string{
		"auth_method": "jwt",
	}

	// Add standard claims
	if v, ok := claims["sub"].(string); ok {
		metadata["subject"] = v
	}
	if v, ok := claims["iss"].(string); ok {
		metadata["issuer"] = v
	}
	if v, ok := claims["email"].(string); ok {
		metadata["email"] = v
	}

	// Apply claim mappings
	for jwtClaim, metadataKey := range config.ClaimMappings {
		if value := extractClaim(claims, jwtClaim); value != "" {
			metadata[metadataKey] = value
		}
	}

	// Extract groups if configured
	if config.GroupsClaim != "" {
		if groups := extractClaim(claims, config.GroupsClaim); groups != "" {
			metadata["groups"] = groups
		}
	}

	return metadata
}

// extractClaim extracts a claim value as a string
func extractClaim(claims map[string]interface{}, claimName string) string {
	if value, ok := claims[claimName]; ok {
		switch v := value.(type) {
		case string:
			return v
		case []interface{}:
			// For array claims like groups
			strs := make([]string, len(v))
			for i, item := range v {
				strs[i] = fmt.Sprintf("%v", item)
			}
			return strings.Join(strs, ",")
		default:
			return fmt.Sprintf("%v", v)
		}
	}
	return ""
}
