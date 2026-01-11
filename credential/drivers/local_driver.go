package drivers

import (
	"context"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
)

// LocalDriver fetches static credentials stored directly in the credential spec
// This is based on the existing LocalFetcher logic from cred/local_fetcher.go
type LocalDriver struct {
	logger *logger.GatedLogger
}

// LocalDriverFactory creates LocalDriver instances
type LocalDriverFactory struct{}

// Type returns the driver type
func (f *LocalDriverFactory) Type() string {
	return "local"
}

// Create instantiates a new LocalDriver
func (f *LocalDriverFactory) Create(config map[string]string, logger *logger.GatedLogger) (credential.SourceDriver, error) {
	return &LocalDriver{
		logger: logger,
	}, nil
}

// ValidateConfig validates driver-specific configuration
// Local driver doesn't require any configuration
func (f *LocalDriverFactory) ValidateConfig(config map[string]string) error {
	return nil // No configuration needed for local driver
}

// MintCredential retrieves static credential data from the spec's SourceParams
func (d *LocalDriver) MintCredential(ctx context.Context, spec *credential.CredSpec) (map[string]interface{}, time.Duration, string, error) {
	// Local credentials are always static (no TTL, no lease)
	rawData := make(map[string]interface{})

	// Copy SourceParams to rawData as interface map
	for key, value := range spec.SourceParams {
		rawData[key] = value
	}

	if d.logger != nil {
		d.logger.Debug("fetched static credentials from local source",
			logger.String("spec", spec.Name),
			logger.String("type", spec.Type),
		)
	}

	// Return:
	// - rawData: credential fields from SourceParams
	// - leaseTTL: 0 (static credentials have no TTL)
	// - leaseID: "" (static credentials have no lease)
	// - error: nil
	return rawData, 0, "", nil
}

// Revoke is a no-op for static credentials
func (d *LocalDriver) Revoke(ctx context.Context, leaseID string) error {
	// Static credentials cannot be revoked
	// This is best-effort, so return nil
	return nil
}

// Type returns the driver type
func (d *LocalDriver) Type() string {
	return "local"
}

// Cleanup releases resources (no-op for local driver)
func (d *LocalDriver) Cleanup(ctx context.Context) error {
	return nil
}
