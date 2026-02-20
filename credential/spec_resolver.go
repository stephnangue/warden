package credential

import (
	"context"
	"fmt"

	"github.com/stephnangue/warden/logger"
)

// SpecResolver handles credential spec lookup and validation.
// It provides a focused abstraction for resolving specs by name from the config store.
//
// Responsibilities:
//   - Lookup CredSpec by name from ConfigStoreAccessor
//   - Return clear error messages when specs are not found
//
// This component was extracted from Manager to:
//   - Reduce Manager's dependency count
//   - Improve testability (can mock ConfigStoreAccessor only)
//   - Provide single responsibility (spec resolution)
type SpecResolver struct {
	configStore ConfigStoreAccessor
	logger      *logger.GatedLogger
}

// NewSpecResolver creates a new SpecResolver instance
func NewSpecResolver(configStore ConfigStoreAccessor, logger *logger.GatedLogger) *SpecResolver {
	return &SpecResolver{
		configStore: configStore,
		logger:      logger,
	}
}

// ResolveSpec retrieves a credential spec by name from the config store.
// Returns an error if the spec is not found or cannot be retrieved.
//
// Parameters:
//   - ctx: Context with namespace information
//   - specName: The name of the credential spec to retrieve
//
// Returns the CredSpec or an error with context
func (r *SpecResolver) ResolveSpec(ctx context.Context, specName string) (*CredSpec, error) {
	spec, err := r.configStore.GetSpec(ctx, specName)
	if err != nil {
		return nil, fmt.Errorf("credential spec '%s' not found: %w", specName, err)
	}
	return spec, nil
}

// SpecExists checks if a credential spec exists and is valid.
// Returns true if the spec can be retrieved without error.
// Returns false if configStore is nil.
func (r *SpecResolver) SpecExists(ctx context.Context, specName string) bool {
	if r.configStore == nil {
		return false
	}
	spec, err := r.configStore.GetSpec(ctx, specName)
	return err == nil && spec != nil
}
