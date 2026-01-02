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
	types        map[string]TokenType // name -> TokenType
	prefixToType map[string]TokenType // valuePrefix -> TokenType
}

// NewTokenTypeRegistry creates a new registry
func NewTokenTypeRegistry() *TokenTypeRegistry {
	return &TokenTypeRegistry{
		types:        make(map[string]TokenType),
		prefixToType: make(map[string]TokenType),
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

	return nil
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
