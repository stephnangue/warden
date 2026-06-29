package jwt

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/mitchellh/pointerstructure"
	"github.com/stephnangue/warden/logical"
)

// maxActChainDepth bounds the depth of nested "act" claims walked by
// extractActChain. RFC 8693 §4.1 allows arbitrary nesting; this cap
// protects against IdP misconfiguration or pathological tokens.
const maxActChainDepth = 4

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

// getClaim resolves a claim value. A leading "/" is interpreted as a JSON
// Pointer (RFC 6901) so nested claims can be addressed (e.g.
// "/resource_access/warden/env"); any other string is a literal top-level key,
// which also makes namespaced OIDC keys like "https://warden.io/env" resolve
// as-is. Returns nil when the claim is absent or the pointer cannot be walked
// (fail closed). Mirrors OpenBao's builtin/credential/jwt getClaim, including
// the float -> json.Number coercion so numeric claims stringify predictably.
func getClaim(claims map[string]interface{}, claim string) interface{} {
	var val interface{}
	if !strings.HasPrefix(claim, "/") {
		val = claims[claim]
	} else {
		v, err := pointerstructure.Get(claims, claim)
		if err != nil {
			return nil
		}
		val = v
	}

	switch v := val.(type) {
	case float32:
		return json.Number(strconv.Itoa(int(v)))
	case float64:
		return json.Number(strconv.Itoa(int(v)))
	}
	return val
}

// extractMetadata builds a token metadata map from verified claims using the
// role's claim mappings (source claim -> metadata key, matching OpenBao's
// claim_mappings direction). Resolved values must be strings; a non-string
// mapped claim is an error rather than being flattened. Absent claims are
// skipped. Returns nil when nothing was mapped.
func extractMetadata(claims map[string]interface{}, claimMappings map[string]string) (map[string]string, error) {
	if len(claimMappings) == 0 {
		return nil, nil
	}
	metadata := make(map[string]string)
	for source, target := range claimMappings {
		value := getClaim(claims, source)
		if value == nil {
			continue
		}
		strValue, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("claim %q for metadata key %q is not a string", source, target)
		}
		metadata[target] = strValue
	}
	if len(metadata) == 0 {
		return nil, nil
	}
	return metadata, nil
}

// extractActChain walks the RFC 8693 §4.1 "act" claim chain into a
// flat verified actor list. Returns nil when no "act" claim is present.
// Terminates without erroring on malformed layers (non-object, missing
// "sub", non-string "sub") and on chains deeper than maxActChainDepth.
//
// Example input:
//
//	{"act": {"sub": "broker-beta", "act": {"sub": "agents/alpha"}}}
//
// Example output:
//
//	[{Subject: "broker-beta", Verified: true},
//	 {Subject: "agents/alpha", Verified: true}]
func extractActChain(claims map[string]interface{}) []logical.ActorRef {
	var actors []logical.ActorRef
	current := claims
	for depth := 0; depth < maxActChainDepth; depth++ {
		raw, ok := current["act"]
		if !ok {
			break
		}
		act, ok := raw.(map[string]interface{})
		if !ok {
			break // malformed: act must be a JSON object
		}
		sub, ok := act["sub"].(string)
		if !ok || sub == "" {
			break // malformed: layer must carry a non-empty string sub
		}
		actors = append(actors, logical.ActorRef{Subject: sub, Verified: true})
		current = act
	}
	return actors
}

// extractGroupsClaim extracts a string slice from a JWT claim.
// Handles: []interface{} (standard JSON array), string (single group),
// and comma-separated string.
func extractGroupsClaim(claims map[string]interface{}, claimName string) []string {
	value, ok := claims[claimName]
	if !ok {
		return nil
	}

	switch v := value.(type) {
	case []interface{}:
		groups := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				groups = append(groups, s)
			}
		}
		return groups
	case string:
		if v == "" {
			return nil
		}
		if strings.Contains(v, ",") {
			parts := strings.Split(v, ",")
			groups := make([]string, 0, len(parts))
			for _, p := range parts {
				if s := strings.TrimSpace(p); s != "" {
					groups = append(groups, s)
				}
			}
			return groups
		}
		return []string{v}
	default:
		return nil
	}
}
