package credential

import (
	"errors"
	"sync"
	"time"
)

// CredSpec defines a credential specification that describes how to mint a particular
// credential from a source. It binds a credential type (e.g., "aws_access_keys",
// "gcp_access_token") to a named CredSource and carries type-specific parameters
// in Config (such as mint_method, scopes, target_service_account, etc.).
//
// When a client request requires credentials, the credential manager looks up the
// CredSpec by name, resolves the referenced CredSource, and calls the source driver's
// MintCredential with this spec. The driver uses Config to determine what kind of
// credential to produce and how to scope it.
//
// Specs may also carry TTL constraints (MinTTL/MaxTTL) that bound the lifetime of
// issued credentials, and a RotationPeriod for types that embed their own credentials
// (e.g., Azure specs with pre-provisioned service principal secrets).
type CredSpec struct {
	// Core identity
	Name string // Spec name (unique identifier)
	Type string // Credential type (e.g., "aws_access_keys", "vault_token")

	// Source configuration
	Source string            // Reference to CredSource
	Config map[string]string // Type-specific parameters (path, role_name, etc.)

	// Constraints
	MinTTL time.Duration // Minimum TTL for issued credentials
	MaxTTL time.Duration // Maximum TTL for issued credentials

	// Rotation
	RotationPeriod time.Duration // Period for rotating credentials stored in the spec (0 means no rotation)
}

// CredSpecRegistry manages credential specifications with thread-safe operations
type CredSpecRegistry struct {
	specs map[string]*CredSpec
	mu    sync.RWMutex
}

// NewCredSpecRegistry creates a new credential spec registry
func NewCredSpecRegistry() *CredSpecRegistry {
	return &CredSpecRegistry{
		specs: make(map[string]*CredSpec),
	}
}

// Register adds a credential spec to the registry
// Returns an error if the spec is nil or if a spec with the same name already exists
func (r *CredSpecRegistry) Register(spec *CredSpec) error {
	if spec == nil {
		return errors.New("cannot register nil spec")
	}
	if spec.Name == "" {
		return errors.New("spec name cannot be empty")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.specs[spec.Name]; exists {
		return ErrSpecAlreadyExists
	}

	r.specs[spec.Name] = spec
	return nil
}

// Get retrieves a credential spec by name
func (r *CredSpecRegistry) Get(name string) (*CredSpec, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	spec, ok := r.specs[name]
	return spec, ok
}

// List returns all registered specs
func (r *CredSpecRegistry) List() []*CredSpec {
	r.mu.RLock()
	defer r.mu.RUnlock()

	specs := make([]*CredSpec, 0, len(r.specs))
	for _, spec := range r.specs {
		specs = append(specs, spec)
	}
	return specs
}

// Delete removes a spec from the registry
func (r *CredSpecRegistry) Delete(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.specs[name]; !exists {
		return false
	}

	delete(r.specs, name)
	return true
}

// Exists checks if a spec with the given name exists
func (r *CredSpecRegistry) Exists(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	_, exists := r.specs[name]
	return exists
}

// Count returns the number of registered specs
func (r *CredSpecRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return len(r.specs)
}
