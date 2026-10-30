package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

// TokenTypeMetadata describes a token type's characteristics
type TokenTypeMetadata struct {
	// Name is the canonical type identifier (TypeServiceToken,
	// TypeIdentityToken)
	Name string

	// IDPrefix used in token ID computation (e.g., "wds_", "wdi_")
	IDPrefix string

	// ValuePrefix used to detect token type from value (e.g., "wds.").
	// Empty string means no prefix detection
	ValuePrefix string

	// LegacyValuePrefix is a value prefix the type issued before ValuePrefix:
	// a presented value carrying it is still detected as this type, but no
	// value is issued with it. Empty when there is none.
	LegacyValuePrefix string

	// Description for documentation/logging
	Description string

	// DefaultTTL is the recommended TTL for this token type (0 = use system default)
	DefaultTTL time.Duration

	// Stateless marks a type whose value carries the whole token: an entry of
	// it is never written to storage, has no accessor and is never indexed by
	// one, and is rebuilt from the value when the cache does not hold it.
	Stateless bool
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
	// E.g., "token" for a service token, "credential" for an identity token.
	// This is used for deterministic token value validation after loading from storage
	LookupKey() string
}

// TransparentTokenType is a TokenType that participates in transparent
// (implicit) authentication: clients present a credential (JWT, TLS cert,
// SA token, SVID) directly with each request rather than acquiring a Warden
// bearer token via an explicit login.
//
// Token types implementing this interface auto-enroll in the family of
// transparent-auth behaviors (cache-only persistence, the explicit-login
// guard, deterministic-ID collision handling). The registry uses these
// methods so the call sites enforcing those behaviors keep no type list.
// Which credential a request carries, and where, is the auth method's
// business (logical.CredentialFormatProvider).
type TransparentTokenType interface {
	TokenType

	// LookupValue produces the deterministic input that ComputeID hashes
	// into the byID-cache key: one key per (mount, credential), whatever
	// role a request asks for. Including mountAccessor in the input
	// prevents cache contamination across two mounts presented the same
	// credential.
	LookupValue(credential, mountAccessor string) string

	// IsTransparent always returns true; the method exists so the
	// registry can ask "is this transparent?" without callers needing
	// to maintain a hardcoded type list.
	IsTransparent() bool
}

// tokenIDHashLen is the length of the hash part of a token ID.
const tokenIDHashLen = 32

// hashTokenID returns the hash part of a token ID: the first 32 hex characters
// of the SHA-256 of lookupValue.
func hashTokenID(lookupValue string) string {
	return tokenID("", lookupValue)
}

// tokenID returns prefix followed by hashTokenID(lookupValue), built in one
// allocation: every request presenting a token computes it.
func tokenID(prefix, lookupValue string) string {
	h := sha256.Sum256([]byte(lookupValue))
	var hexHash [tokenIDHashLen]byte
	hex.Encode(hexHash[:], h[:tokenIDHashLen/2])
	var b strings.Builder
	b.Grow(len(prefix) + tokenIDHashLen)
	b.WriteString(prefix)
	b.Write(hexHash[:])
	return b.String()
}
