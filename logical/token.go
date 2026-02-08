package logical

import (
	"context"
	"sync"
	"time"
)

// TokenEntry represents a token with comprehensive metadata for
// namespace-aware, secure token management.
type TokenEntry struct {
	// Core Identity (Two-Tier Cache)
	ID       string // Primary hash-based ID (Tier 1: in-memory cache)
	Accessor string // Reference ID for safe operations (Tier 2: in-memory cache)
	Type     string // Token type (user_pass, aws_access_keys, etc.)

	// Namespace Binding
	NamespaceID   string // Namespace UUID where token was created
	NamespacePath string // Human-readable namespace path (e.g., "/org1/team1/")

	// Creation Context
	CreatedAt      time.Time // Token creation timestamp
	CreatedByIP    string    // IP address at creation
	CreatedByReqID string    // Request ID that created token

	// Authorization
	PrincipalID  string // Associated principal
	RoleName     string // Associated role

	// Lifecycle
	ExpireAt time.Time // Expiration time

	// Token Data
	Data map[string]string // Type-specific credential data

	// Usage Tracking
	mu   sync.RWMutex
	used bool // One-time use flag

    //Policies attached to this token 
    Policies       []string

    // Credential spec for this token if any
    CredentialSpec string
}

// MarkUsed marks the token as used (for one-time use tokens)
func (t *TokenEntry) MarkUsed() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.used = true
}

// IsUsed returns whether the token has been used
func (t *TokenEntry) IsUsed() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.used
}

type TokenAccess interface {
	ResolveToken(ctx context.Context, tokenValue string) (string, string, error)
	GetToken(tokenValue string) *TokenEntry
}

type ContextClientIPKey string

const ClientIPKey ContextClientIPKey = "client_ip"
