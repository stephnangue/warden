package logical

import (
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
)

// Auth is the resulting authentication information that is part of
// Response for auth backends. It's also attached to Request objects and
// defines the authentication used for the request. This value is audit logged.
type Auth struct {
	// Policies is the list of policies that the authenticated user
	// is associated with.
	Policies []string `json:"policies" mapstructure:"policies" structs:"policies"`

    // Credential spec as a result of the authentification if any
    CredentialSpec string

	// ClientToken is the token that is generated for the authentication.
	ClientToken string `json:"client_token" mapstructure:"client_token" structs:"client_token"`

	// Accessor is the identifier for the ClientToken. This can be used
	// to perform management functionalities (especially revocation) when
	// ClientToken in the audit logs are obfuscated. Accessor can be used
	// to revoke a ClientToken and to lookup the capabilities of the ClientToken,
	// both without actually knowing the ClientToken.
	TokenAccessor string `json:"token_accessor" mapstructure:"token_accessor" structs:"token_accessor"`

	// TokenType is the type of token being requested
	TokenType string `json:"token_type"`

	// PolicyResults is the set of policies that grant the token access to the
	// requesting path.
	PolicyResults *sdklogical.PolicyResults `json:"policy_results"`

	PrincipalID  string 

	RoleName     string

	TokenTTL     time.Duration

	NamespaceID   string // Namespace UUID

	NamespacePath string // Namespace path

	ClientIP string

}

// AuthData contains the authentication data used to generate a token.
type AuthData struct {
	PrincipalID    string    // Principal identifier
	RoleName       string    // Associated role
	ExpireAt       time.Time // Token expiration
	CredentialSpec string
	Policies       []string
	ClientIP       string
	TokenValue     string // External token value (e.g., JWT for transparent mode)
}