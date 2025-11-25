package api

import (
	"context"
	"fmt"
	"sync"

	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/provider"
)

// ProviderRegistry manages all available provider factories
type ProviderRegistry struct {
	factories  map[string]provider.Factory
	mu         sync.RWMutex
	logger     logger.Logger
}

// NewProviderRegistry creates a new provider registry
func NewProviderRegistry(logger logger.Logger) *ProviderRegistry {
	registry := &ProviderRegistry{
		factories: make(map[string]provider.Factory),
		logger: logger,
	}

	return registry
}

func (r *ProviderRegistry) Register(ctx context.Context, factory provider.Factory) error {
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

func (r *ProviderRegistry) GetFactory(providerType string) (provider.Factory, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	factory, exists := r.factories[providerType]
	if !exists {
		return nil, fmt.Errorf("unknown provider type: %s", providerType)
	}

	return factory, nil
}

func (r *ProviderRegistry) ListTypes() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	types := make([]string, 0, len(r.factories))
	for providerType := range r.factories {
		types = append(types, providerType)
	}

	return types
}