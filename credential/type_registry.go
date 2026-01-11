package credential

import (
	"fmt"
	"sync"
)

// TypeRegistry manages registered credential types
// This mirrors the TokenTypeRegistry pattern in core/token_registry.go
type TypeRegistry struct {
	mu    sync.RWMutex
	types map[string]Type // name -> Type
}

// NewTypeRegistry creates a new credential type registry
func NewTypeRegistry() *TypeRegistry {
	return &TypeRegistry{
		types: make(map[string]Type),
	}
}

// Register adds a credential type to the registry
func (r *TypeRegistry) Register(credType Type) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	meta := credType.Metadata()

	// Check for duplicate registration
	if _, exists := r.types[meta.Name]; exists {
		return fmt.Errorf("%w: %s", ErrTypeAlreadyRegistered, meta.Name)
	}

	r.types[meta.Name] = credType
	return nil
}

// GetByName retrieves a credential type by its name
func (r *TypeRegistry) GetByName(name string) (Type, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	credType, exists := r.types[name]
	if !exists {
		return nil, fmt.Errorf("%w: %s", ErrTypeNotFound, name)
	}

	return credType, nil
}

// ListTypes returns all registered credential type names
func (r *TypeRegistry) ListTypes() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.types))
	for name := range r.types {
		names = append(names, name)
	}
	return names
}

// HasType checks if a credential type is registered with the given name
func (r *TypeRegistry) HasType(typeName string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	_, exists := r.types[typeName]
	return exists
}
