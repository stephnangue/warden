package spiffe

import "time"

// SPIFFERole binds a SPIFFE trust domain to a set of token policies. One role
// serves both SVID types: an X.509-SVID (TLS client cert) or a JWT-SVID (bearer)
// whose verified SPIFFE ID is in trust_domain and matches allowed_spiffe_ids.
//
// bound_audiences applies only to JWT-SVIDs (X.509-SVIDs have no audience). It is
// optional at write time but required at JWT-SVID login: a JWT-SVID login against
// a role with no bound_audiences fails closed (JWT-SVID mandates an audience).
type SPIFFERole struct {
	Name              string   `json:"name"`
	Description       string   `json:"description,omitempty"`
	TrustDomain       string   `json:"trust_domain"`                 // SPIFFE trust domain this role binds to (required)
	AllowedSPIFFEIDs  []string `json:"allowed_spiffe_ids,omitempty"` // optional SPIFFE-ID segment patterns
	BoundAudiences    []string `json:"bound_audiences,omitempty"`    // required for JWT-SVID logins
	TokenPolicies     []string `json:"token_policies"`
	TokenTTL          string   `json:"token_ttl"`
	TokenType         string   `json:"token_type,omitempty"`
	CredSpecName      string   `json:"cred_spec_name,omitempty"`
	GroupsClaim       string   `json:"groups_claim,omitempty"`        // JWT-SVID group claim → policies
	GroupPolicyPrefix string   `json:"group_policy_prefix,omitempty"` // prefix for group policies (default group-)
}

// ParseTokenTTL parses the TokenTTL string to a time.Duration.
func (r *SPIFFERole) ParseTokenTTL() (time.Duration, error) {
	if r.TokenTTL == "" {
		return time.Hour, nil
	}
	return time.ParseDuration(r.TokenTTL)
}
