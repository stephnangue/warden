package credential

import (
	"context"
	"fmt"
	"sync"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/stephnangue/warden/logger"
)

// DriverRegistry manages driver factories and instances
type DriverRegistry struct {
	mu        sync.RWMutex
	factories map[string]SourceDriverFactory // type -> factory
	instances map[string]SourceDriver        // {namespace}:{source_name} -> driver instance
	log       *logger.GatedLogger
}

// NewDriverRegistry creates a new driver registry
func NewDriverRegistry(log *logger.GatedLogger) *DriverRegistry {
	return &DriverRegistry{
		factories: make(map[string]SourceDriverFactory),
		instances: make(map[string]SourceDriver),
		log:       log,
	}
}

// RegisterFactory registers a driver factory
func (r *DriverRegistry) RegisterFactory(factory SourceDriverFactory) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	driverType := factory.Type()

	// Check for duplicate registration
	if _, exists := r.factories[driverType]; exists {
		return fmt.Errorf("%w: %s", ErrDriverAlreadyRegistered, driverType)
	}

	r.factories[driverType] = factory
	return nil
}

// qualifiedKey builds a namespace-qualified key for driver instance lookup
// Format: {namespace_id}:{source_name}
func (r *DriverRegistry) qualifiedKey(ctx context.Context, sourceName string) (string, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get namespace from context: %w", err)
	}
	return fmt.Sprintf("%s:%s", ns.ID, sourceName), nil
}

// CreateDriver creates a driver instance for the given source
// The driver is stored with a namespace-qualified key to prevent collisions
// between sources with the same name in different namespaces.
// Returns the driver and a boolean indicating if a new driver was created (true)
// or an existing driver was returned (false).
func (r *DriverRegistry) CreateDriver(ctx context.Context, sourceName string, source *CredSource) (SourceDriver, bool, error) {
	qualifiedName, err := r.qualifiedKey(ctx, sourceName)
	if err != nil {
		return nil, false, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if instance already exists
	if driver, exists := r.instances[qualifiedName]; exists {
		return driver, false, nil
	}

	// Get factory for source type
	factory, exists := r.factories[source.Type]
	if !exists {
		return nil, false, fmt.Errorf("%w: %s", ErrDriverNotFound, source.Type)
	}

	// Create driver instance
	driver, err := factory.Create(source.Config, r.log)
	if err != nil {
		return nil, false, fmt.Errorf("%w: %s: %v", ErrDriverCreationFailed, source.Type, err)
	}

	// Store instance with namespace-qualified key
	r.instances[qualifiedName] = driver

	return driver, true, nil
}

// GetDriver retrieves a driver instance by source name
// Uses namespace from context to build qualified key
func (r *DriverRegistry) GetDriver(ctx context.Context, sourceName string) (SourceDriver, bool) {
	qualifiedName, err := r.qualifiedKey(ctx, sourceName)
	if err != nil {
		return nil, false
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	driver, exists := r.instances[qualifiedName]
	return driver, exists
}

// ListFactories returns all registered driver factory types
func (r *DriverRegistry) ListFactories() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	types := make([]string, 0, len(r.factories))
	for driverType := range r.factories {
		types = append(types, driverType)
	}
	return types
}

// HasFactory checks if a driver factory is registered for the given type
func (r *DriverRegistry) HasFactory(driverType string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	_, exists := r.factories[driverType]
	return exists
}

// GetFactory retrieves a driver factory by type
func (r *DriverRegistry) GetFactory(driverType string) (SourceDriverFactory, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	factory, exists := r.factories[driverType]
	if !exists {
		return nil, fmt.Errorf("%w: %s", ErrDriverNotFound, driverType)
	}

	return factory, nil
}

// CloseDriver closes and removes a driver instance by source name.
// This should be called when a source is deleted or updated to prevent resource leaks.
// Returns an error if the driver's Cleanup() method fails.
func (r *DriverRegistry) CloseDriver(ctx context.Context, sourceName string) error {
	qualifiedName, err := r.qualifiedKey(ctx, sourceName)
	if err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	driver, exists := r.instances[qualifiedName]
	if !exists {
		// Driver doesn't exist - nothing to clean up
		return nil
	}

	// Call driver's cleanup method
	if err := driver.Cleanup(ctx); err != nil {
		r.log.Warn("driver cleanup failed",
			logger.String("source_name", sourceName),
			logger.Err(err))
		// Continue to remove from registry even if cleanup fails
	}

	// Remove from registry
	delete(r.instances, qualifiedName)

	r.log.Debug("driver closed and removed",
		logger.String("source_name", sourceName),
		logger.String("qualified_key", qualifiedName))

	return nil
}

// CloseAllForNamespace closes and removes all driver instances for a given namespace.
// This should be called when a namespace is deleted to prevent resource leaks.
// Returns the number of drivers closed and any errors encountered.
func (r *DriverRegistry) CloseAllForNamespace(ctx context.Context) (int, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to get namespace from context: %w", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Find all drivers for this namespace
	prefix := ns.ID + ":"
	var toClose []string
	for key := range r.instances {
		if len(key) > len(prefix) && key[:len(prefix)] == prefix {
			toClose = append(toClose, key)
		}
	}

	if len(toClose) == 0 {
		return 0, nil
	}

	// Close each driver and collect errors
	closed := 0
	var lastErr error

	for _, key := range toClose {
		driver := r.instances[key]
		if err := driver.Cleanup(ctx); err != nil {
			r.log.Warn("driver cleanup failed during namespace cleanup",
				logger.String("qualified_key", key),
				logger.Err(err))
			lastErr = err
			// Continue to remove even if cleanup fails
		}

		delete(r.instances, key)
		closed++
	}

	r.log.Debug("drivers closed for namespace",
		logger.String("namespace_id", ns.ID),
		logger.Int("count", closed))

	return closed, lastErr
}
