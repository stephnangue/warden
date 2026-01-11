package credential

import (
	"fmt"
	"sync"
)

// DriverRegistry manages driver factories and instances
type DriverRegistry struct {
	mu        sync.RWMutex
	factories map[string]SourceDriverFactory // type -> factory
	instances map[string]SourceDriver        // source_name -> driver instance
}

// NewDriverRegistry creates a new driver registry
func NewDriverRegistry() *DriverRegistry {
	return &DriverRegistry{
		factories: make(map[string]SourceDriverFactory),
		instances: make(map[string]SourceDriver),
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

// CreateDriver creates a driver instance for the given source
func (r *DriverRegistry) CreateDriver(sourceName string, source *CredSource) (SourceDriver, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if instance already exists
	if driver, exists := r.instances[sourceName]; exists {
		return driver, nil
	}

	// Get factory for source type
	factory, exists := r.factories[source.Type]
	if !exists {
		return nil, fmt.Errorf("%w: %s", ErrDriverNotFound, source.Type)
	}

	// Create driver instance
	driver, err := factory.Create(source.Config, nil) // logger will be passed when integrated
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrDriverCreationFailed, source.Type, err)
	}

	// Store instance
	r.instances[sourceName] = driver

	return driver, nil
}

// GetDriver retrieves a driver instance by source name
func (r *DriverRegistry) GetDriver(sourceName string) (SourceDriver, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	driver, exists := r.instances[sourceName]
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
