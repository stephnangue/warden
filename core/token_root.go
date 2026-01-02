package core

import (
	"sync"
	"time"
)

// RootTokenManager handles the lifecycle of the root token.
// It provides thread-safe storage and management of the current root token.
type RootTokenManager struct {
	mu           sync.RWMutex
	currentToken string    // The actual token value (cws.*)
	tokenID      string    // Computed hash-based ID (wtkn_*)
	generated    time.Time // When the token was generated
}

// NewRootTokenManager creates a new root token manager.
func NewRootTokenManager() *RootTokenManager {
	return &RootTokenManager{}
}

// SetRootToken stores the root token and its ID.
// This should be called after successfully generating a new root token.
func (rtm *RootTokenManager) SetRootToken(tokenValue, tokenID string) {
	rtm.mu.Lock()
	defer rtm.mu.Unlock()
	rtm.currentToken = tokenValue
	rtm.tokenID = tokenID
	rtm.generated = time.Now()
}

// GetCurrentRootToken returns the current root token value.
// Returns empty string if no root token exists.
func (rtm *RootTokenManager) GetCurrentRootToken() string {
	rtm.mu.RLock()
	defer rtm.mu.RUnlock()
	return rtm.currentToken
}

// GetCurrentRootTokenID returns the current root token ID (hash).
// Returns empty string if no root token exists.
func (rtm *RootTokenManager) GetCurrentRootTokenID() string {
	rtm.mu.RLock()
	defer rtm.mu.RUnlock()
	return rtm.tokenID
}

// ClearRootToken removes the current root token from memory.
// This is called during revocation.
func (rtm *RootTokenManager) ClearRootToken() {
	rtm.mu.Lock()
	defer rtm.mu.Unlock()
	rtm.currentToken = ""
	rtm.tokenID = ""
	rtm.generated = time.Time{}
}

// IsRootToken checks if the given token value is the current root token.
func (rtm *RootTokenManager) IsRootToken(tokenValue string) bool {
	rtm.mu.RLock()
	defer rtm.mu.RUnlock()
	return rtm.currentToken == tokenValue
}

// HasRootToken returns true if a root token currently exists.
func (rtm *RootTokenManager) HasRootToken() bool {
	rtm.mu.RLock()
	defer rtm.mu.RUnlock()
	return rtm.currentToken != ""
}
