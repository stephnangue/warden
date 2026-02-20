package credential

import (
	"context"
	"fmt"
	"time"

	"github.com/stephnangue/warden/logger"
)

// MintingService handles credential minting with automatic orphaned lease cleanup.
// It provides a focused abstraction for calling driver.MintCredential() and ensuring
// that any minted credentials are properly cleaned up if subsequent processing fails.
//
// Responsibilities:
//   - Call driver.MintCredential() to obtain raw credential data
//   - Automatically revoke orphaned leases if processing fails (deferred cleanup)
//   - Log minting failures and cleanup attempts
//   - Provide clean separation between minting and parsing/validation
//
// This component was extracted from Manager to:
//   - Improve testability (can test orphaned lease cleanup in isolation)
//   - Provide single responsibility (credential minting with cleanup)
//   - Enable future enhancements (retry logic, circuit breakers, etc.)
//   - Separate minting concerns from orchestration logic
type MintingService struct {
	logger *logger.GatedLogger
}

// NewMintingService creates a new MintingService instance
func NewMintingService(logger *logger.GatedLogger) *MintingService {
	return &MintingService{
		logger: logger,
	}
}

// MintWithCleanup mints a credential and ensures orphaned leases are cleaned up on failure.
//
// The minting pipeline with automatic cleanup:
//  1. Call driver.MintCredential() to obtain raw credential data
//  2. Register deferred cleanup handler for orphaned lease revocation
//  3. Call onSuccess callback with minted data (typically parse/validate)
//  4. If onSuccess succeeds, mark success and skip cleanup
//  5. If onSuccess fails, automatically revoke the lease at source
//
// This pattern prevents orphaned credentials from accumulating at sources:
//   - Vault leases that are never revoked
//   - AWS IAM users/access keys that are never deleted
//   - Azure service principal credentials that remain valid
//   - Database user accounts that are never dropped
//
// Parameters:
//   - ctx: Context for the minting operation
//   - driver: The source driver to mint credentials from
//   - spec: The credential spec defining minting parameters
//   - onSuccess: Callback to process minted data (parse/validate)
//
// Returns an error if minting fails or if onSuccess callback fails
func (s *MintingService) MintWithCleanup(
	ctx context.Context,
	driver SourceDriver,
	spec *CredSpec,
	onSuccess func(rawData map[string]interface{}, leaseTTL time.Duration, leaseID string) error,
) error {
	// Step 1: Mint credential from driver
	rawData, leaseTTL, leaseID, err := driver.MintCredential(ctx, spec)
	if err != nil {
		return fmt.Errorf("failed to fetch credential: %w", err)
	}

	// Step 2: Register deferred cleanup for orphaned lease prevention
	// Track whether processing succeeds - if not, revoke the lease
	success := false
	defer func() {
		if !success && leaseID != "" {
			s.revokeOrphanedLease(driver, leaseID, spec.Source)
		}
	}()

	// Step 3: Call success handler to process minted data
	// This typically involves parsing and validating the credential
	if err := onSuccess(rawData, leaseTTL, leaseID); err != nil {
		return err // Deferred cleanup will revoke the lease
	}

	// Step 4: Mark success to prevent deferred cleanup
	success = true
	return nil
}

// revokeOrphanedLease attempts to revoke a lease that was minted but not successfully processed.
// This is a best-effort operation that logs errors but does not fail the overall operation.
// Uses a fresh background context since the original context may have been cancelled.
func (s *MintingService) revokeOrphanedLease(driver SourceDriver, leaseID, sourceName string) {
	// Use background context with timeout since original may be cancelled
	revokeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := driver.Revoke(revokeCtx, leaseID); err != nil {
		s.logger.Warn("failed to revoke orphaned lease after issuance failure",
			logger.String("lease_id", leaseID),
			logger.String("source", sourceName),
			logger.Err(err))
	} else {
		s.logger.Debug("revoked orphaned lease after issuance failure",
			logger.String("lease_id", leaseID),
			logger.String("source", sourceName))
	}
}
