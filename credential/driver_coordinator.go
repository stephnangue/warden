package credential

import (
	"context"
	"fmt"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/stephnangue/warden/logger"
)

// DriverCoordinator handles driver lifecycle management and coordination.
// It provides a focused abstraction for getting, creating, and closing driver instances.
//
// Responsibilities:
//   - Get existing driver instances from DriverRegistry
//   - Create new driver instances when needed (lazy initialization)
//   - Close driver instances on source deletion or update
//   - Log driver creation events with namespace context
//
// This component was extracted from Manager to:
//   - Reduce Manager's dependency count
//   - Improve testability (can mock DriverRegistry and ConfigStoreAccessor)
//   - Provide single responsibility (driver lifecycle)
//   - Centralize driver creation logic (used by Manager and ExpirationManager)
type DriverCoordinator struct {
	driverRegistry *DriverRegistry
	configStore    ConfigStoreAccessor
	logger         *logger.GatedLogger
}

// NewDriverCoordinator creates a new DriverCoordinator instance
func NewDriverCoordinator(
	driverRegistry *DriverRegistry,
	configStore ConfigStoreAccessor,
	logger *logger.GatedLogger,
) *DriverCoordinator {
	return &DriverCoordinator{
		driverRegistry: driverRegistry,
		configStore:    configStore,
		logger:         logger,
	}
}

// GetOrCreateDriver retrieves an existing driver or creates one if it doesn't exist.
// This is needed during credential issuance and revocation (especially after server restart
// when drivers aren't cached yet).
//
// Parameters:
//   - ctx: Context with namespace information
//   - sourceName: Name of the credential source
//
// Returns the driver instance or an error
func (c *DriverCoordinator) GetOrCreateDriver(ctx context.Context, sourceName string) (SourceDriver, error) {
	// First try to get existing driver
	if driver, ok := c.driverRegistry.GetDriver(ctx, sourceName); ok {
		return driver, nil
	}

	// Driver doesn't exist, fetch source config and create it
	credSource, err := c.configStore.GetSource(ctx, sourceName)
	if err != nil {
		return nil, fmt.Errorf("source '%s' not found: %w", sourceName, err)
	}

	driver, created, err := c.driverRegistry.CreateDriver(ctx, sourceName, credSource)
	if err != nil {
		return nil, fmt.Errorf("failed to create driver for source '%s': %w", sourceName, err)
	}

	// Only log when a new driver was actually created (not when returning existing)
	if created {
		ns, _ := namespace.FromContext(ctx)
		c.logger.Debug("credential source driver created",
			logger.String("namespace", ns.ID),
			logger.String("source_name", sourceName),
			logger.String("source_type", credSource.Type))
	}

	return driver, nil
}

// CloseDriver closes and removes a driver instance by source name.
// This should be called when a source is deleted or updated to prevent resource leaks.
//
// Parameters:
//   - ctx: Context with namespace information
//   - sourceName: Name of the credential source
//
// Returns an error if cleanup fails
func (c *DriverCoordinator) CloseDriver(ctx context.Context, sourceName string) error {
	return c.driverRegistry.CloseDriver(ctx, sourceName)
}

// CloseAllForNamespace closes and removes all driver instances for a given namespace.
// This should be called when a namespace is deleted to prevent resource leaks.
//
// Parameters:
//   - ctx: Context with namespace information
//
// Returns the number of drivers closed and any error encountered
func (c *DriverCoordinator) CloseAllForNamespace(ctx context.Context) (int, error) {
	return c.driverRegistry.CloseAllForNamespace(ctx)
}
