package core

import (
	"errors"
	"fmt"
	"strings"
	"sync"
)

var (
	// ErrTypeAlreadyRegistered is returned when attempting to register a duplicate token type
	ErrTypeAlreadyRegistered = errors.New("token type already registered")

	// ErrTypeNotFound is returned when a token type is not found in the registry
	ErrTypeNotFound = errors.New("token type not found")
)

// TokenTypeRegistry manages registered token types
type TokenTypeRegistry struct {
	mu           sync.RWMutex
	types        map[string]TokenType            // name -> TokenType
	prefixToType map[string]TokenType            // valuePrefix -> TokenType
	authMethod   map[string]TransparentTokenType // AuthMethodType -> TransparentTokenType
}

// NewTokenTypeRegistry creates a new registry
func NewTokenTypeRegistry() *TokenTypeRegistry {
	return &TokenTypeRegistry{
		types:        make(map[string]TokenType),
		prefixToType: make(map[string]TokenType),
		authMethod:   make(map[string]TransparentTokenType),
	}
}

// Register adds a token type to the registry
func (r *TokenTypeRegistry) Register(tokenType TokenType) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	meta := tokenType.Metadata()

	// Check for duplicate registration
	if _, exists := r.types[meta.Name]; exists {
		return fmt.Errorf("%w: %s", ErrTypeAlreadyRegistered, meta.Name)
	}

	r.types[meta.Name] = tokenType

	// Register prefix mapping if prefix exists
	if meta.ValuePrefix != "" {
		r.prefixToType[meta.ValuePrefix] = tokenType
	}

	// Index transparent token types by AuthMethodType so callers (the
	// implicit-auth dispatcher, the system-introspect aggregator, the
	// explicit-login guard) can ask "what TokenType serves mounts of
	// type X?" without a hardcoded switch.
	if meta.AuthMethodType != "" {
		if tt, ok := tokenType.(TransparentTokenType); ok {
			r.authMethod[meta.AuthMethodType] = tt
		}
	}

	return nil
}

// IsTransparent returns true if the named token type implements
// TransparentTokenType and self-reports as transparent. Returns false for
// unknown types and for non-transparent types (e.g. warden_token).
func (r *TokenTypeRegistry) IsTransparent(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	tokenType, ok := r.types[name]
	if !ok {
		return false
	}
	tt, ok := tokenType.(TransparentTokenType)
	if !ok {
		return false
	}
	return tt.IsTransparent()
}

// GetTransparentTokenTypeForAuthMethod returns the TransparentTokenType
// registered to serve mounts whose entry.Type equals the given mountType.
// Returns nil if no transparent type is registered for that mount type.
func (r *TokenTypeRegistry) GetTransparentTokenTypeForAuthMethod(mountType string) TransparentTokenType {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.authMethod[mountType]
}

// GetByName retrieves a token type by its name
func (r *TokenTypeRegistry) GetByName(name string) (TokenType, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	tokenType, exists := r.types[name]
	if !exists {
		return nil, fmt.Errorf("%w: %s", ErrTypeNotFound, name)
	}

	return tokenType, nil
}

// DetectType determines token type from value format
func (r *TokenTypeRegistry) DetectType(tokenValue string) (TokenType, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Try prefix matching
	for prefix, tokenType := range r.prefixToType {
		if strings.HasPrefix(tokenValue, prefix) {
			return tokenType, nil
		}
	}

	// No match found
	return nil, fmt.Errorf("%w: could not detect type from value", ErrTypeNotFound)
}

// ListTypes returns all registered token type names
func (r *TokenTypeRegistry) ListTypes() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.types))
	for name := range r.types {
		names = append(names, name)
	}
	return names
}
