package api

import (
	"context"
	"fmt"
	"sync"

	"github.com/stephnangue/warden/audit"
	"github.com/stephnangue/warden/logger"
)

// AuditDeviceRegistry manages all available audit device factories
type AuditDeviceRegistry struct {
	factories  map[string]audit.Factory
	mu         sync.RWMutex
	logger     logger.Logger
}

// NewAuditDeviceRegistry creates a new audit device registry
func NewAuditDeviceRegistry(logger logger.Logger) *AuditDeviceRegistry {
	registry := &AuditDeviceRegistry{
		factories: make(map[string]audit.Factory),
		logger: logger,
	}

	return registry
}

func (r *AuditDeviceRegistry) Register(ctx context.Context, factory audit.Factory) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.factories[factory.Type()]; exists {
		return fmt.Errorf("factory for type '%s' already registered", factory.Type())
	}

	err := factory.Initialize(r.logger.WithSystem("factory"))
	if err == nil {
		r.factories[factory.Type()] = factory
	} else {
		r.logger.Errorf("failed to initialize factory", logger.Err(err))
	}

	return nil
}

func (r *AuditDeviceRegistry) GetFactory(deviceType string) (audit.Factory, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	factory, exists := r.factories[deviceType]
	if !exists {
		return nil, fmt.Errorf("unknown device type: %s", deviceType)
	}

	return factory, nil
}

func (r *AuditDeviceRegistry) ListTypes() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	types := make([]string, 0, len(r.factories))
	for deviceType := range r.factories {
		types = append(types, deviceType)
	}

	return types
}