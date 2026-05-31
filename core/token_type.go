package core

import (
	"context"
	"time"
)

// TokenTypeMetadata describes a token type's characteristics
type TokenTypeMetadata struct {
	// Name is the canonical type identifier (e.g., "warden_token", "jwt_role")
	Name string

	// IDPrefix used in token ID computation (e.g., "wtkn_", "jwtr_", "crtr_")
	IDPrefix string

	// ValuePrefix used to detect token type from value (e.g., "usr-", "AKIA", "cws.")
	// Empty string means no prefix detection
	ValuePrefix string

	// Description for documentation/logging
	Description string

	// DefaultTTL is the recommended TTL for this token type (0 = use system default)
	DefaultTTL time.Duration

	// AuthMethodType is the mount-table entry.Type string this TokenType
	// serves (e.g. "jwt", "cert", "kubernetes"). Empty for non-auth-method
	// types (warden_token). Used by the registry to map a mount entry to
	// the TransparentTokenType that handles its transparent-auth flow,
	// without callers having to maintain a parallel switch.
	AuthMethodType string
}

// TokenType defines the interface for pluggable token types
type TokenType interface {
	// Metadata returns the type's metadata
	Metadata() TokenTypeMetadata

	// Generate creates a new token value and populates the token entry
	// Returns the token value(s) to return to the client as map[string]string
	// The implementation should:
	// 1. Generate cryptographically secure random values
	// 2. Populate entry.Data with all necessary fields
	// 3. Return the client-facing values (e.g., {"username": "...", "password": "..."})
	Generate(ctx context.Context, authData *AuthData, entry *TokenEntry) (map[string]string, error)

	// ValidateValue checks if a token value matches the expected format
	ValidateValue(tokenValue string) bool

	// ComputeID generates the hash-based token ID from the lookup value
	ComputeID(lookupValue string) string

	// LookupKey returns the key name in the Data map that holds the lookup value
	// E.g., for warden it's "token", for jwt_role it's "token"
	// This is used for deterministic token value validation after loading from storage
	LookupKey() string
}

// TransparentTokenType is a TokenType that participates in transparent
// (implicit) authentication: clients present a credential (JWT, TLS cert,
// SA token, future cloud-native equivalents) directly with each request
// rather than acquiring a Warden bearer token via an explicit login.
//
// Token types implementing this interface auto-enroll in the family of
// transparent-auth behaviors (cache-only persistence, the explicit-login
// guard, the "transparent" display alias, deterministic-ID collision
// handling). The registry uses these methods so adding a new transparent
// auth method does not require touching the call sites that enforce
// those behaviors.
type TransparentTokenType interface {
	TokenType

	// LookupValue produces the deterministic input that ComputeID hashes
	// into the byID-cache key. Including mountAccessor in the input
	// prevents cache contamination across two mounts of the same auth
	// type with overlapping role names + the same credential.
	LookupValue(credential, mountAccessor, role string) string

	// IsTransparent always returns true; the method exists so the
	// registry can ask "is this transparent?" without callers needing
	// to maintain a hardcoded type list.
	IsTransparent() bool

	// CredentialFormat reports the discovery-level credential kind this
	// type accepts. Today's values: "jwt" (generic JWT bearer, validated
	// by JWKS/OIDC discovery), "cert" (TLS client cert), "k8s_sa_jwt"
	// (Kubernetes SA JWT, validated by TokenReview), future "stsv4"
	// (AWS IAM signed STS request), etc.
	//
	// Granularity matters: the introspect aggregator uses exact-match
	// filtering on this value to avoid fan-out to mounts that can't
	// authenticate the caller's credential. performImplicitAuth groups
	// same-wire-format values (e.g. "jwt" and "k8s_sa_jwt" share JWT
	// bearer extraction) inside its dispatch switch.
	CredentialFormat() string
}
