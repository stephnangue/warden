package credential

import (
	"errors"
	"sync"
	"time"
)

// Credential type constants
const (
	TypeDatabaseUserPass = "database_userpass"
	TypeAWSAccessKeys    = "aws_access_keys"
)

// Source type constants
const (
	SourceTypeLocal = "local"
	SourceTypeVault = "hashicorp_vault"
)

// Category constants for credential categorization
const (
	CategoryDatabase = "database"
	CategoryCloudIAM = "cloud_iam"
	CategoryOAuth    = "oauth"
	CategoryPKI      = "pki"
	CategoryK8s      = "kubernetes"
	CategoryAPI      = "api"
)

// Credential represents a credential with enhanced metadata
type Credential struct {
	// Type information
	Type     string // Credential type name (e.g., "database_userpass", "aws_access_keys")
	Category string // Category for routing/organization

	// Lifecycle
	LeaseTTL time.Duration // TTL for dynamic credentials (0 for static)
	LeaseID  string        // Lease ID for revocation (empty for static)
	TokenID  string        // Session token this credential is bound to
	IssuedAt time.Time     // When the credential was issued

	// Data
	Data map[string]string // Type-specific credential data

	// Metadata
	SourceType string // Which driver issued this credential
	Revocable  bool   // Whether this credential can be revoked
	SpecName   string // Which spec created this credential (for tracking/audit)
}

// IsExpired checks if the credential has expired
func (c *Credential) IsExpired() bool {
	if c.LeaseTTL == 0 {
		return false // Static credentials don't expire
	}
	return time.Since(c.IssuedAt) >= c.LeaseTTL
}

// RemainingTTL returns the remaining time until expiration
func (c *Credential) RemainingTTL() time.Duration {
	if c.LeaseTTL == 0 {
		return 0 // Static credentials have no TTL
	}
	remaining := c.LeaseTTL - time.Since(c.IssuedAt)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// ShouldRotate checks if the credential should be rotated based on a threshold
// threshold is a percentage (0.0 to 1.0) of TTL remaining
func (c *Credential) ShouldRotate(threshold float64) bool {
	if c.LeaseTTL == 0 || !c.Revocable {
		return false // Static or non-revocable credentials don't rotate
	}
	remaining := c.RemainingTTL()
	return float64(remaining) <= float64(c.LeaseTTL)*threshold
}

type CredSource struct {
	Name   string
	Type   string // local, hashicorp_vault, aws_secret_manager, aws_iam, azure_key_vault, cgp_secret_manager
	Config map[string]string
}

type CredSourceRegistry struct {
	sources map[string]*CredSource
	mu      sync.RWMutex
}

func NewCredSourceRegistry() *CredSourceRegistry {
	return &CredSourceRegistry{
		sources: make(map[string]*CredSource),
	}
}

// Register adds a credential source to the registry
// Returns an error if the source is invalid or if a source with the same name already exists
func (r *CredSourceRegistry) Register(source CredSource) error {
	if source.Name == "" {
		return errors.New("source name cannot be empty")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.sources[source.Name]; exists {
		return ErrSourceAlreadyExists
	}

	r.sources[source.Name] = &source
	return nil
}

// Get retrieves a credential source by name (alias for GetSource for consistency)
func (r *CredSourceRegistry) Get(name string) (*CredSource, bool) {
	return r.GetSource(name)
}

// GetSource retrieves a credential source by name
func (r *CredSourceRegistry) GetSource(name string) (*CredSource, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	source := r.sources[name]
	if source == nil {
		return nil, false
	}
	return source, true
}

// List returns all registered sources
func (r *CredSourceRegistry) List() []*CredSource {
	r.mu.RLock()
	defer r.mu.RUnlock()

	sources := make([]*CredSource, 0, len(r.sources))
	for _, source := range r.sources {
		sources = append(sources, source)
	}
	return sources
}

// Delete removes a source from the registry
func (r *CredSourceRegistry) Delete(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.sources[name]; !exists {
		return false
	}

	delete(r.sources, name)
	return true
}

// Exists checks if a source with the given name exists
func (r *CredSourceRegistry) Exists(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	_, exists := r.sources[name]
	return exists
}

// Count returns the number of registered sources
func (r *CredSourceRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return len(r.sources)
}
