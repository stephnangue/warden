package credential

import (
	"time"
)

// CredSpec defines a credential specification that describes how to mint a particular
// credential from a source. It binds a credential type (e.g., "aws_access_keys",
// "gcp_access_token") to a named CredSource and carries type-specific parameters
// in Config (such as mint_method, scopes, target_service_account, etc.).
//
// When a client request requires credentials, the credential manager looks up the
// CredSpec by name, resolves the referenced CredSource, and calls the source driver's
// MintCredential with this spec. The driver uses Config to determine what kind of
// credential to produce and how to scope it.
//
// Specs may also carry TTL constraints (MinTTL/MaxTTL) that bound the lifetime of
// issued credentials, and a RotationPeriod for types that embed their own credentials
// (e.g., Azure specs with pre-provisioned service principal secrets).
type CredSpec struct {
	// Core identity
	Name string // Spec name (unique identifier)
	Type string // Credential type (e.g., "aws_access_keys", "vault_token")

	// Source configuration
	Source string // Reference to CredSource
	Config Config // Type-specific parameters (path, role_name, etc.)

	// Constraints
	MinTTL time.Duration // Minimum TTL for issued credentials
	MaxTTL time.Duration // Maximum TTL for issued credentials

	// Rotation
	RotationPeriod time.Duration // Period for rotating credentials stored in the spec (0 means no rotation)
}
