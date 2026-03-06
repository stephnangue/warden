package jwt

import (
	"time"
)

// JWTRole represents a role configuration for JWT authentication.
// Used for both runtime and storage (TokenTTL stored as string for JSON readability).
type JWTRole struct {
	Name             string         `json:"name"`
	BoundAudiences   []string       `json:"bound_audiences,omitempty"`
	BoundSubject     string         `json:"bound_subject,omitempty"`
	BoundClaims      map[string]any `json:"bound_claims,omitempty"`
	BoundURIPatterns []string       `json:"bound_uri_patterns,omitempty"` // Segment-aware URI patterns (e.g. spiffe://+/dept/*)
	URIClaim         string         `json:"uri_claim,omitempty"`          // Claim to match against URI patterns (default: "sub")
	TokenPolicies    []string       `json:"token_policies"`
	TokenTTL         string         `json:"token_ttl"`
	TokenType        string         `json:"token_type,omitempty"`
	UserClaim        string         `json:"user_claim,omitempty"`
	CredSpecName     string         `json:"cred_spec_name,omitempty"`
	MaxAge           string         `json:"max_age,omitempty"`            // Max time since iat (e.g. "30m", "1h"). Empty = no check.
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
