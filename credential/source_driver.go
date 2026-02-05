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

	// SensitiveConfigFields returns the list of config keys that should be masked in output
	SensitiveConfigFields() []string
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

// Rotatable is an optional interface for drivers that support credential rotation.
// Credential sources can implement this to allow periodic rotation of their
// authentication credentials (e.g., Vault AppRole secret_id, AWS IAM keys).
//
// The rotation is split into three phases to ensure disruption-free rotation:
//  1. PrepareRotation: Generate new credentials (old still valid)
//  2. CommitRotation: Activate new credentials in driver (after persist)
//  3. CleanupRotation: Destroy old credentials (best-effort)
//
// This design ensures new credentials are persisted BEFORE old ones are destroyed,
// preventing loss of access if a crash occurs during rotation.
type Rotatable interface {
	// SupportsRotation returns true if this driver instance can rotate its credentials.
	// This depends on the driver configuration - for example, Vault AppRole with
	// role_name supports rotation, but token auth may not.
	SupportsRotation() bool

	// PrepareRotation generates new credentials WITHOUT destroying old ones.
	// Both old and new credentials remain valid during the overlap period.
	//
	// Returns:
	//   - newConfig: updated config map with new credentials (will be persisted)
	//   - cleanupConfig: driver-specific config needed to destroy old credentials
	//     Examples:
	//       - Vault AppRole: {"secret_id_accessor": "old-accessor-uuid"}
	//       - AWS IAM: {"access_key_id": "old-key-id"}
	//   - error: if new credential generation fails
	//
	// IMPORTANT: This method must NOT modify driver internal state or destroy old credentials.
	PrepareRotation(ctx context.Context) (newConfig map[string]string, cleanupConfig map[string]string, err error)

	// CommitRotation activates new credentials in the driver's internal state.
	// Called AFTER the new config has been persisted to storage.
	//
	// The driver should:
	//   1. Update its internal config with newConfig
	//   2. Re-authenticate using the new credentials
	//
	// Returns error if activation fails (e.g., re-authentication fails).
	CommitRotation(ctx context.Context, newConfig map[string]string) error

	// CleanupRotation destroys old credentials using the cleanupConfig from PrepareRotation.
	// Called AFTER CommitRotation succeeds and new credentials are active.
	//
	// Returns error if cleanup fails. The RotationManager will:
	//   1. Retry cleanup with exponential backoff (up to 3 immediate attempts)
	//   2. If all retries fail, persist cleanupConfig to storage
	//   3. Retry persisted cleanups daily (max 7 days, then abandon)
	//
	// The cleanupConfig format is driver-specific.
	CleanupRotation(ctx context.Context, cleanupConfig map[string]string) error
}
