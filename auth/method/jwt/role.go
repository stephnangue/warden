package jwt

import (
	"time"
)

// JWTRole represents a role configuration for JWT authentication.
// Used for both runtime and storage (TokenTTL stored as string for JSON readability).
type JWTRole struct {
	Name              string         `json:"name"`
	Description       string         `json:"description,omitempty"`
	BoundAudiences    []string       `json:"bound_audiences,omitempty"`
	BoundSubject      string         `json:"bound_subject,omitempty"`
	BoundClaims       map[string]any `json:"bound_claims,omitempty"`
	TokenPolicies     []string       `json:"token_policies"`
	TokenTTL          string         `json:"token_ttl"`
	TokenType         string         `json:"token_type,omitempty"`
	UserClaim         string         `json:"user_claim,omitempty"`
	CredSpecName      string         `json:"cred_spec_name,omitempty"`
	GroupsClaim       string         `json:"groups_claim,omitempty"`        // Override global groups_claim for this role
	GroupPolicyPrefix string         `json:"group_policy_prefix,omitempty"` // Override global group_policy_prefix for this role
	MaxAge            string         `json:"max_age,omitempty"`             // Max time since iat (e.g. "30m", "1h"). Empty = no check.

	// MetadataClaims maps a source claim to the token metadata key it
	// populates (source -> key, matching OpenBao's claim_mappings). The
	// source is resolved by getClaim: a leading "/" is a JSON Pointer
	// (RFC 6901) for nested claims, otherwise a literal top-level key.
	// Resolved values must be strings; populated onto the token's Metadata
	// and matched by token_metadata policy conditions.
	MetadataClaims map[string]string `json:"metadata_claims,omitempty"`
}

// ParseTokenTTL parses the TokenTTL string to a time.Duration.
func (r *JWTRole) ParseTokenTTL() (time.Duration, error) {
	if r.TokenTTL == "" {
		return time.Hour, nil
	}
	return time.ParseDuration(r.TokenTTL)
}

// ParseMaxAge parses the MaxAge string to a time.Duration.
// Returns 0 if MaxAge is not set.
func (r *JWTRole) ParseMaxAge() (time.Duration, error) {
	if r.MaxAge == "" {
		return 0, nil
	}
	return time.ParseDuration(r.MaxAge)
}
