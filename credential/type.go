package credential

import (
	"context"
	"time"
)

// TypeMetadata describes a credential type's characteristics
type TypeMetadata struct {
	// Name is the canonical type identifier (e.g., "database_userpass", "aws_access_keys")
	Name string

	// Category for organization (e.g., "database", "cloud_iam", "oauth")
	Category string

	// Description for documentation/logging
	Description string

	// DefaultTTL is the recommended TTL for this credential type (0 = use system default)
	DefaultTTL time.Duration
}

// Type defines the interface for pluggable credential types
// This mirrors the TokenType pattern in core/token_type.go
type Type interface {
	// Metadata returns the type's metadata
	Metadata() TypeMetadata

	// ValidateSourceParams validates the SourceParams for a CredSpec
	// This allows credential types to validate their configuration before creation
	// sourceName parameter allows type-specific validation based on the driver type
	// Returns an error if required params are missing or invalid
	ValidateSourceParams(params map[string]string, sourceName string) error

	// Parse converts raw credential data from source into structured Credential
	// rawData contains the source-specific credential fields
	// leaseTTL is the lease duration from the source (0 for static)
	// leaseID is the lease identifier for revocation (empty for static)
	Parse(rawData map[string]interface{}, leaseTTL time.Duration, leaseID string) (*Credential, error)

	// Validate checks if credential data is well-formed
	Validate(cred *Credential) error

	// Revoke releases the credential (best-effort)
	// Returns nil if revocation is not supported or succeeds
	Revoke(ctx context.Context, cred *Credential, driver SourceDriver) error

	// CanRotate indicates if this type supports proactive rotation
	CanRotate() bool
}
