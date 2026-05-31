package kubernetes

import "time"

// KubernetesRole represents a role configuration for the kubernetes auth
// method. Used for both runtime evaluation and on-disk storage; durations
// are stored as strings for JSON readability.
type KubernetesRole struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`

	// BoundServiceAccountNames is the list of service account names this
	// role accepts. "*" matches any. Validation refuses ("*",...) paired
	// with ("*",...) for BoundServiceAccountNamespaces — at least one of
	// the two must be a concrete value.
	BoundServiceAccountNames []string `json:"bound_service_account_names"`

	// BoundServiceAccountNamespaces is the list of namespaces the workload
	// SA must live in. "*" matches any (subject to the same validation).
	BoundServiceAccountNamespaces []string `json:"bound_service_account_namespaces"`

	// Audience is sent as spec.audiences in the TokenReview request.
	// The workload JWT must declare this audience or the kube-apiserver
	// rejects the review. Empty = no audience binding for this role
	// (TokenReview will accept the token's natural audiences).
	Audience string `json:"audience,omitempty"`

	TokenPolicies []string `json:"token_policies"`
	TokenTTL      string   `json:"token_ttl"`
	TokenType     string   `json:"token_type,omitempty"`
	CredSpecName  string   `json:"cred_spec_name,omitempty"`

	// MaxAge optionally caps the elapsed time since the JWT's iat claim.
	// Empty = no freshness check. Same shape as JWTRole.MaxAge.
	MaxAge string `json:"max_age,omitempty"`
}

// ParseTokenTTL parses the TokenTTL string to a time.Duration.
// Returns 1h when empty (mirrors JWT method default).
func (r *KubernetesRole) ParseTokenTTL() (time.Duration, error) {
	if r.TokenTTL == "" {
		return time.Hour, nil
	}
	return time.ParseDuration(r.TokenTTL)
}

// ParseMaxAge parses the MaxAge string to a time.Duration.
// Returns 0 (no check) if MaxAge is not set.
func (r *KubernetesRole) ParseMaxAge() (time.Duration, error) {
	if r.MaxAge == "" {
		return 0, nil
	}
	return time.ParseDuration(r.MaxAge)
}
