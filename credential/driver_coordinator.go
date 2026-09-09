package credential

import (
	"context"
	"errors"
	"fmt"

	"github.com/stephnangue/warden/internal/namespace"
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
	// A cached instance is the common case and costs one map read.
	if driver, ok := c.driverRegistry.GetDriver(ctx, sourceName); ok {
		return driver, nil
	}

	// Building an instance reads the source and then installs, and the two cannot
	// be done under one lock — the read goes through the config store, the install
	// through the registry. A source update landing in between used to leave the
	// driver built from the config read before it, permanently: nothing re-checks a
	// registry hit, so that instance was served until the next update or a restart.
	//
	// So the generation is read first, and the install refused if it moved while
	// the source was being read. Config updates are rare, and each retry starts by
	// re-checking the registry, so this settles immediately in practice; the bound
	// exists only so a pathological update storm cannot spin here.
	const maxAttempts = 3
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if driver, ok := c.driverRegistry.GetDriver(ctx, sourceName); ok {
			return driver, nil
		}

		generation, err := c.driverRegistry.Generation(ctx, sourceName)
		if err != nil {
			return nil, err
		}

		credSource, err := c.configStore.GetSource(ctx, sourceName)
		if err != nil {
			return nil, fmt.Errorf("source '%s' not found: %w", sourceName, err)
		}

		driver, created, err := c.driverRegistry.CreateDriver(ctx, sourceName, credSource, generation)
		if errors.Is(err, ErrDriverConfigChanged) {
			continue
		}
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

	return nil, fmt.Errorf("failed to create driver for source '%s': config kept changing after %d attempts", sourceName, maxAttempts)
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
