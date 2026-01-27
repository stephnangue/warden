package core

import "time"

// TokenTypeMetadata describes a token type's characteristics
type TokenTypeMetadata struct {
	// Name is the canonical type identifier (e.g., "user_pass", "aws_access_keys")
	Name string

	// IDPrefix used in token ID computation (e.g., "usrp_", "awsk_", "wtkn_")
	IDPrefix string

	// ValuePrefix used to detect token type from value (e.g., "usr-", "AKIA", "cws.")
	// Empty string means no prefix detection
	ValuePrefix string

	// Description for documentation/logging
	Description string

	// DefaultTTL is the recommended TTL for this token type (0 = use system default)
	DefaultTTL time.Duration
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
	Generate(authData *AuthData, entry *TokenEntry) (map[string]string, error)

	// ValidateValue checks if a token value matches the expected format
	ValidateValue(tokenValue string) bool

	// ComputeID generates the hash-based token ID from the lookup value
	ComputeID(lookupValue string) string

	// LookupKey returns the key name in the Data map that holds the lookup value
	// E.g., for AWS it's "access_key_id", for user_pass it's "username", for warden it's "token"
	// This is used for deterministic token value validation after loading from storage
	LookupKey() string
}
