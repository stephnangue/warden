package cert

import "time"

// CertRole represents a role configuration for certificate authentication.
// Used for both runtime and storage (TokenTTL stored as string for JSON readability).
type CertRole struct {
	Name                       string   `json:"name"`
	Description                string   `json:"description,omitempty"`
	AllowedCommonNames         []string `json:"allowed_common_names,omitempty"`
	AllowedDNSSANs             []string `json:"allowed_dns_sans,omitempty"`
	AllowedEmailSANs           []string `json:"allowed_email_sans,omitempty"`
	AllowedURISANs             []string `json:"allowed_uri_sans,omitempty"`
	AllowedOrganizationalUnits []string `json:"allowed_organizational_units,omitempty"`
	AllowedOrganizations       []string `json:"allowed_organizations,omitempty"`
	Certificate                string   `json:"certificate,omitempty"` // Role-specific CA PEM (overrides global)
	TokenPolicies              []string `json:"token_policies"`
	TokenTTL                   string   `json:"token_ttl"`
	TokenType                  string   `json:"token_type,omitempty"`
	CredSpecName               string   `json:"cred_spec_name,omitempty"`
	PrincipalClaim             string   `json:"principal_claim,omitempty"`
}

// ParseTokenTTL parses the TokenTTL string to a time.Duration.
func (r *CertRole) ParseTokenTTL() (time.Duration, error) {
	if r.TokenTTL == "" {
		return time.Hour, nil
	}
	return time.ParseDuration(r.TokenTTL)
}
