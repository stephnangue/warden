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
	Type     string // Token type (warden_token, jwt_role, cert_role)

	// Namespace Binding
	NamespaceID   string // ID (not UUID) of the namespace the token was created in
	NamespacePath string // Human-readable namespace path (e.g., "/org1/team1/")

	// Creation Context
	CreatedAt      time.Time // Token creation timestamp
	CreatedByIP    string    // IP address at creation
	CreatedByReqID string    // Request ID that created token

	// Authorization
	PrincipalID string // Associated principal

	// RoleName is the role the token runs under. A login sets it on the token;
	// an admission token carries none, and core writes the role granted for
	// one request onto that request's copy of the entry, never onto the
	// stored one.
	RoleName string

	// MountAccessor is the stable identifier of the auth mount that issued
	// this login. It discriminates principals that different mounts (trusting
	// different identity providers) may map to the same PrincipalID, so a
	// federated identity assertion can carry a globally-unique subject.
	MountAccessor string

	// Lifecycle
	ExpireAt time.Time // Expiration time

	// Token Data
	Data map[string]string // Type-specific credential data

	// Metadata holds verified, login-derived identity attributes (mapped
	// from JWT claims, certificate fields, service-account attributes, etc.)
	// that token_metadata policy conditions match against. Distinct from
	// Data, which is type-specific credential material. Never caller-supplied.
	//
	// Read only, on every copy: the map is shared with the stored entry, and on
	// an admission token's per-request copy with the membership cached for every
	// request of that credential. Code that needs a different map builds a new
	// one.
	Metadata map[string]string

	// Usage Tracking
	mu   sync.RWMutex
	used bool // One-time use flag

	// Policies attached to this token. On an admission token's per-request
	// copy, the granted role's policies, shared with the published role: read
	// only.
	Policies []string

	// Credential spec for this token if any. Like RoleName, written per
	// request for an admission token.
	CredentialSpec string

	// Actors persists the verified RFC 8693 "act" delegation chain (the JWT
	// "act" claim) so that it survives transparent-mode token caching.
	// Populated by the auth method at login time.
	Actors []ActorRef

	// Admission is what the auth method verified at login. Every copy of this
	// entry shares the one *Admission (immutable but for its atomically
	// replaced membership cache). It is never
	// serialized, so a token reloaded from storage has none (transparent
	// tokens are cache-only and never reloaded).
	Admission *Admission `json:"-"`
}

// Copy returns a copy of t for one request, or nil for a nil t. The copy's own
// fields may be reassigned freely; the maps, slices and the *Admission it holds
// are shared with t and are read only. Safe to call while other goroutines
// read t.
func (t *TokenEntry) Copy() *TokenEntry {
	if t == nil {
		return nil
	}
	return &TokenEntry{
		ID:             t.ID,
		Accessor:       t.Accessor,
		Type:           t.Type,
		NamespaceID:    t.NamespaceID,
		NamespacePath:  t.NamespacePath,
		CreatedAt:      t.CreatedAt,
		CreatedByIP:    t.CreatedByIP,
		CreatedByReqID: t.CreatedByReqID,
		PrincipalID:    t.PrincipalID,
		RoleName:       t.RoleName,
		MountAccessor:  t.MountAccessor,
		ExpireAt:       t.ExpireAt,
		Data:           t.Data,
		Metadata:       t.Metadata,
		used:           t.IsUsed(),
		Policies:       t.Policies,
		CredentialSpec: t.CredentialSpec,
		Actors:         t.Actors,
		Admission:      t.Admission,
	}
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
