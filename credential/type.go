package credential

import (
	"context"
	"time"
)

// CredentialFieldSchema describes a field in credential data
type CredentialFieldSchema struct {
	// Description explains what this field contains
	Description string

	// Sensitive indicates the field should be masked in output
	Sensitive bool
}

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

	// ValidateConfig validates the Config for a CredSpec
	// This allows credential types to validate their configuration before creation
	// sourceType parameter enables source-specific validation rules:
	// - "local": validates that config contains the credential values directly
	// - "vault": validates that config contains Vault path/mount configuration
	// Returns an error if required config values are missing or invalid
	ValidateConfig(config map[string]string, sourceType string) error

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

	// FieldSchemas returns metadata about the credential's data fields
	// Used for masking sensitive fields in responses
	FieldSchemas() map[string]*CredentialFieldSchema
}
