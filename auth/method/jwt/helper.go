package jwt

import (
	"fmt"
	"strings"
)

// validateBoundClaims validates that JWT claims match the bound claims
func validateBoundClaims(claims map[string]interface{}, boundClaims map[string]any) error {
	for key, expectedValue := range boundClaims {
		actualValue, exists := claims[key]
		if !exists {
			return fmt.Errorf("required claim '%s' not found in JWT", key)
		}

		// Simple equality check - in production you'd want more sophisticated matching
		if fmt.Sprintf("%v", actualValue) != fmt.Sprintf("%v", expectedValue) {
			return fmt.Errorf("claim '%s' does not match expected value", key)
		}
	}
	return nil
}

// buildJWTMetadata extracts metadata from JWT claims
func buildJWTMetadata(claims map[string]interface{}, config *JWTAuthConfig) map[string]string {
	metadata := map[string]string{
		"auth_method": config.Name,
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
