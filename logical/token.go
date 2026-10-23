package logical

import (
	"context"
	"sync"
	"time"
)

// Token type names, as TokenEntry.Type, Auth.TokenType and the audit and CEL
// token_type values carry them.
const (
	// TokenTypeIdentity is the token of a caller admitted by a transparent
	// auth method: it carries the verified identity and its facts, and no
	// capabilities of its own (a role grants them per request). It lives in
	// the cache only, one per credential and auth mount, and no value is ever
	// handed out for it: the caller presents its own credential every time.
	TokenTypeIdentity = "identity_token"

	// TokenTypeService is a bearer token Warden issues and persists, carrying
	// its own policies (the root token is one).
	TokenTypeService = "service_token"
)

// TokenEntry represents a token with comprehensive metadata for
// namespace-aware, secure token management.
type TokenEntry struct {
	// Core Identity (Two-Tier Cache)
	ID       string // Primary hash-based ID (Tier 1: in-memory cache)
	Accessor string // Reference ID for safe operations (Tier 2: in-memory cache)
	Type     string // Token type (TokenTypeIdentity, TokenTypeService)

	// Namespace Binding
	NamespaceID   string // ID (not UUID) of the namespace the token was created in
	NamespacePath string // Human-readable namespace path (e.g., "/org1/team1/")

	// Creation Context
	CreatedAt      time.Time // Token creation timestamp
	CreatedByIP    string    // IP address at creation
	CreatedByReqID string    // Request ID that created token

	// Authorization
	PrincipalID string // Associated principal

	// RoleName is the role the token runs under for one request. No token is
	// issued with one: core writes the role granted for one request onto that
	// request's copy of an admission token's entry, never onto the stored one.
	RoleName string

	// MountAccessor is the stable identifier of the auth mount that issued
	// this login. It discriminates principals that different mounts (trusting
	// different identity providers) may map to the same PrincipalID, so a
	// federated identity assertion can carry a globally-unique subject.
	MountAccessor string

	// Lifecycle
	ExpireAt time.Time // Expiration time

	// Data is type-specific credential data. Read only once the entry is
	// stored, like every field Copy shares (see Copy).
	Data map[string]string

	// Metadata holds verified, login-derived identity attributes (mapped
	// from JWT claims, certificate fields, service-account attributes, etc.)
	// that token_metadata policy conditions match against. Distinct from
	// Data, which is type-specific credential material. Never caller-supplied.
	//
	// Read only, on every copy: the map is shared with the stored entry, and on
	// an admission token's per-request copy with the membership cached for every
	// request of that credential. Code that needs a different map builds a new
	// one (see Copy).
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
// (Data, Metadata, Policies, Actors, Admission) are shared with t and are read
// only: never index-assign, delete from, append onto, clear, sort or otherwise
// write into them, on any entry. TestTokenEntrySharedFieldsNotMutatedInPlace
// enforces this over the module, allowing only the creation sites it lists.
// Safe to call while other goroutines read t.
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
	// ResolveToken returns the principal of the token tokenValue names.
	ResolveToken(ctx context.Context, tokenValue string) (string, error)
	GetToken(tokenValue string) *TokenEntry
}

type ContextClientIPKey string

const ClientIPKey ContextClientIPKey = "client_ip"
