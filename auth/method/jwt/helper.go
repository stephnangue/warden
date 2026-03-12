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

// parseNumericClaim extracts an int64 timestamp from a JWT claim value.
// JWT numeric values may be float64 (JSON decode), int64, or int.
func parseNumericClaim(value any) (int64, bool) {
	switch v := value.(type) {
	case float64:
		return int64(v), true
	case int64:
		return v, true
	case int:
		return int64(v), true
	default:
		return 0, false
	}
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
