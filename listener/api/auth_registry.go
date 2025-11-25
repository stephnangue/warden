package api

import (
	"context"
	"fmt"
	"sync"

	"github.com/stephnangue/warden/auth"
	"github.com/stephnangue/warden/logger"
)

// AuthRegistry manages all available auth method factories
type AuthRegistry struct {
	factories  map[string]auth.Factory
	mu         sync.RWMutex
	logger     logger.Logger
}

// NewAuthRegistry creates a new auth method registry
func NewAuthRegistry(logger logger.Logger) *AuthRegistry {
	registry := &AuthRegistry{
		factories: make(map[string]auth.Factory),
		logger: logger,
	}

	return registry
}

func (r *AuthRegistry) Register(ctx context.Context, factory auth.Factory) error {
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

func (r *AuthRegistry) GetFactory(methodType string) (auth.Factory, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	factory, exists := r.factories[methodType]
	if !exists {
		return nil, fmt.Errorf("unknown auth method type: %s", methodType)
	}

	return factory, nil
}

func (r *AuthRegistry) ListTypes() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	types := make([]string, 0, len(r.factories))
	for methodType := range r.factories {
		types = append(types, methodType)
	}

	return types
}