package jwt

import (
	"time"
)

// JWTRole represents a role configuration for JWT authentication
type JWTRole struct {
	Name           string         `json:"name"`
	BoundAudiences []string       `json:"bound_audiences,omitempty"`
	BoundSubject   string         `json:"bound_subject,omitempty"`
	BoundClaims    map[string]any `json:"bound_claims,omitempty"`
	TokenPolicies  []string       `json:"token_policies"`
	TokenTTL       time.Duration  `json:"token_ttl"`
	TokenType      string         `json:"token_type,omitempty"`
	UserClaim      string         `json:"user_claim,omitempty"`
	CredSpecName   string         `json:"cred_spec_name,omitempty"`
}

// StoredRole is the JSON-serializable format for storage
type StoredRole struct {
	Name           string         `json:"name"`
	BoundAudiences []string       `json:"bound_audiences,omitempty"`
	BoundSubject   string         `json:"bound_subject,omitempty"`
	BoundClaims    map[string]any `json:"bound_claims,omitempty"`
	TokenPolicies  []string       `json:"token_policies"`
	TokenTTL       string         `json:"token_ttl"`
	TokenType      string         `json:"token_type,omitempty"`
	UserClaim      string         `json:"user_claim,omitempty"`
	CredSpecName   string         `json:"cred_spec_name,omitempty"`
}
