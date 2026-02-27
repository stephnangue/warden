package credential

import (
	"errors"
	"sync"
	"time"
)

// Credential type constants
const (
	TypeAWSAccessKeys     = "aws_access_keys"
	TypeVaultToken        = "vault_token"
	TypeAzureBearerToken  = "azure_bearer_token"
	TypeGCPAccessToken    = "gcp_access_token"
	TypeGitLabAccessToken = "gitlab_access_token"
	TypeGitHubToken       = "github_token"
	TypeAIAPIKey          = "ai_api_key"
)

// Source type constants
const (
	SourceTypeLocal  = "local"
	SourceTypeVault  = "hvault"
	SourceTypeAWS    = "aws"
	SourceTypeAzure  = "azure"
	SourceTypeGCP    = "gcp"
	SourceTypeGitLab   = "gitlab"
	SourceTypeGitHub   = "github"
	SourceTypeMistral  = "mistral"
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

// Credential represents a minted credential instance returned to gateway requests.
// It is the output of the Manager.IssueCredential pipeline: a SourceDriver produces
// raw data, a credential Type parses it, and the result is stored here with full
// lifecycle metadata.
//
// Provider gateway handlers read Data to inject authentication into proxied requests
// (e.g., Data["access_token"] for Azure/GCP Bearer injection, Data["access_key_id"]
// and Data["secret_access_key"] for AWS SigV4 re-signing).
//
// Each instance is bound to a session token (TokenID) and cached in the Manager.
// Dynamic credentials (LeaseTTL > 0) are tracked by the expiration manager for
// automatic revocation when the token expires.
type Credential struct {
	// Identity
	// CredentialID is the unique identifier for this credential instance.
	// Always a UUID, generated when the credential is minted.
	// This is separate from LeaseID which is the source's revocation handle.
	CredentialID string // UUID - unique identifier for this credential instance

	// Type information
	Type     string // Credential type name (e.g., "aws_access_keys", "vault_token")
	Category string // Category for routing/organization

	// Lifecycle
	LeaseTTL time.Duration // TTL for dynamic credentials (0 for static)
	LeaseID  string        // Lease ID for revocation at source (empty for static)
	TokenID  string        // Session token this credential is bound to
	IssuedAt time.Time     // When the credential was issued

	// Data
	Data map[string]string // Type-specific credential data

	// Metadata
	SourceName string // Name of the credential source (for driver lookup during revocation)
	SourceType string // Type of the driver that issued this credential
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
	Name           string
	Type           string            // local, hvault, aws, azure_key_vault, gcp_secret_manager
	Config         map[string]string
	RotationPeriod time.Duration     // 0 means no rotation
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
