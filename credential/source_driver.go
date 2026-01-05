package credential

import (
	"context"
	"time"

	"github.com/stephnangue/warden/logger"
)

// SourceDriverFactory creates source driver instances
// This mirrors the Provider Factory pattern in provider/interface.go
//
// Configuration Values:
// All config values are passed as map[string]string for consistency with CLI flags.
// Drivers must parse string values to their expected types using the helper functions
// in config_helpers.go (GetInt, GetBool, GetDuration, etc.).
//
// Example:
//
//	func (f *MyDriverFactory) ValidateConfig(config map[string]string) error {
//	    // Validate required fields exist
//	    if err := credential.ValidateRequired(config, "address", "token"); err != nil {
//	        return err
//	    }
//	    // Validate type conversions
//	    if _, err := credential.GetIntRequired(config, "max_retries"); err != nil {
//	        return err
//	    }
//	    return nil
//	}
type SourceDriverFactory interface {
	// Type returns the driver type identifier (e.g., "vault", "aws_secrets_manager", "local")
	Type() string

	// Create instantiates a new driver with the given configuration
	// Config values are strings - use credential.Get* helpers to parse to expected types
	Create(config map[string]string, logger *logger.GatedLogger) (SourceDriver, error)

	// ValidateConfig validates driver-specific configuration
	// Config values are strings - use credential.Get* helpers to validate types
	ValidateConfig(config map[string]string) error
}

// SourceDriver defines the interface for credential source drivers
type SourceDriver interface {
	// MintCredential retrieves or mint raw credential data from the source
	// Takes a CredSpec as input
	// Returns:
	//   - rawData: map of credential fields
	//   - leaseTTL: duration of the lease (0 for static credentials)
	//   - leaseID: identifier for revocation (empty for static)
	//   - error: any error encountered
	MintCredential(ctx context.Context, spec *CredSpec) (map[string]interface{}, time.Duration, string, error)

	// Revoke attempts to revoke a lease/credential (best-effort)
	// Returns nil if revocation is not supported or succeeds
	Revoke(ctx context.Context, leaseID string) error

	// Type returns the driver type
	Type() string

	// Cleanup releases resources
	Cleanup(ctx context.Context) error
}
