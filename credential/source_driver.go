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

// SourceDriver defines the interface for credential source drivers.
// Each driver encapsulates the logic for communicating with a specific credential
// backend (e.g., Vault, AWS IAM/STS, Azure AD, GCP IAM) to mint short-lived
// credentials on behalf of authenticated clients.
//
// The core credential manager calls MintCredential with a CredSpec when a streaming
// request needs credentials. The driver reads spec.Config to decide which API call
// to make (e.g., STS AssumeRole, OAuth2 token exchange, service account impersonation)
// and returns raw credential data that the credential type's Parse method structures
// into a Credential object.
//
// Drivers may optionally implement Rotatable (to rotate their own source credentials)
// and/or SpecRotatable (to rotate credentials embedded in specs).
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

// SpecVerifier is an optional interface for drivers that can verify spec credentials
// at creation time. This is called during ValidateSpec to catch invalid credentials
// early (e.g., wrong GitHub PAT, invalid app_id) rather than failing at gateway time.
//
// Unlike MintCredential, VerifySpec is only called during spec creation/update —
// not on every login or gateway request. Drivers can make lightweight API calls
// here that would be too expensive for the hot path.
type SpecVerifier interface {
	// VerifySpec validates that the spec's credentials are functional by making
	// a lightweight API call to the upstream provider.
	// Returns nil if verification succeeds or is not applicable for this spec config.
	VerifySpec(ctx context.Context, spec *CredSpec) error
}

// Rotatable is an optional interface for drivers that support credential rotation.
// Credential sources can implement this to allow periodic rotation of their
// authentication credentials (e.g., Vault AppRole secret_id, AWS IAM keys).
//
// Rotation uses scheduled credential activation:
//  1. PrepareRotation: Generate new credentials and schedule activation
//  2. [wait activateAfter duration for credential propagation]
//  3. CommitRotation: Activate new credentials in driver (after persist)
//  4. CleanupRotation: Destroy old credentials (best-effort)
//
// Drivers with eventual consistency (AWS, Azure) return a positive activateAfter
// to allow propagation. Drivers with immediate consistency (Vault) return 0.
type Rotatable interface {
	// SupportsRotation returns true if this driver instance can rotate its credentials.
	// This depends on the driver configuration - for example, Vault AppRole with
	// role_name supports rotation, but token auth may not.
	SupportsRotation() bool

	// PrepareRotation generates new credentials and schedules their activation.
	// Both old and new credentials remain valid during the overlap period.
	//
	// Returns:
	//   - newConfig: updated config map with new credentials (will be persisted)
	//   - cleanupConfig: driver-specific config needed to destroy old credentials
	//     Examples:
	//       - Vault AppRole: {"secret_id_accessor": "old-accessor-uuid"}
	//       - AWS IAM: {"access_key_id": "old-key-id"}
	//   - activateAfter: how long to wait before activating (0 = activate immediately).
	//     Drivers with eventual consistency (AWS, Azure) return a positive duration
	//     to allow propagation. Drivers with immediate consistency (Vault) return 0.
	//   - error: if new credential generation fails
	//
	// IMPORTANT: This method must NOT modify driver internal state or destroy old credentials.
	PrepareRotation(ctx context.Context) (newConfig map[string]string, cleanupConfig map[string]string, activateAfter time.Duration, err error)

	// CommitRotation activates new credentials in the driver's internal state.
	// Called AFTER the new config has been persisted to storage and the
	// activateAfter delay has elapsed.
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

// SpecRotatable is an optional interface for drivers that can rotate credentials
// stored in credential specs. This is used when specs contain embedded credentials
// that need periodic rotation (e.g., Azure pre-provisioned service principal credentials).
//
// The source driver uses its own permissions to rotate the spec's credentials.
// For example, an Azure source with Application.ReadWrite.All permission can rotate
// the client_secret of a workload SP stored in a spec.
//
// The rotation follows the same scheduled activation pattern as Rotatable:
//  1. PrepareSpecRotation: Generate new credentials and schedule activation
//  2. [wait activateAfter duration for credential propagation]
//  3. CommitSpecRotation: Signal activation (spec config already updated)
//  4. CleanupSpecRotation: Destroy old credentials (best-effort)
type SpecRotatable interface {
	// SupportsSpecRotation returns true if this driver can rotate credentials in specs.
	// This typically requires the source to have elevated permissions (e.g., Graph API
	// Application.ReadWrite.All for Azure) to manage credentials on other applications.
	SupportsSpecRotation() bool

	// PrepareSpecRotation generates new credentials for the spec and schedules activation.
	// Both old and new credentials remain valid during the overlap period.
	//
	// Returns:
	//   - newConfig: updated spec config map with new credentials (will replace spec.Config)
	//   - cleanupConfig: data needed to destroy old credentials later
	//   - activateAfter: how long to wait before activating (0 = activate immediately)
	//   - error: if new credential generation fails
	//
	// IMPORTANT: This method must NOT destroy old credentials - both must remain valid.
	PrepareSpecRotation(ctx context.Context, spec *CredSpec) (newConfig map[string]string, cleanupConfig map[string]string, activateAfter time.Duration, err error)

	// CommitSpecRotation is called AFTER the spec config has been updated in storage
	// and the activateAfter delay has elapsed.
	// The driver can perform any post-update actions (e.g., clearing caches).
	//
	// Parameters:
	//   - spec: the spec being rotated (with original config, not yet updated)
	//   - newConfig: the new config that was persisted
	CommitSpecRotation(ctx context.Context, spec *CredSpec, newConfig map[string]string) error

	// CleanupSpecRotation destroys old credentials using the cleanupConfig from PrepareSpecRotation.
	// Called AFTER CommitSpecRotation succeeds and new credentials are active.
	//
	// Returns error if cleanup fails. The RotationManager will retry with backoff.
	CleanupSpecRotation(ctx context.Context, cleanupConfig map[string]string) error
}
