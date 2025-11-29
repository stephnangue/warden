package token

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"time"
)

const (
	USER_PASS       = "user_pass"
	AWS_ACCESS_KEYS = "aws_access_keys"
	WARDEN_TOKEN    = "warden_token"
)

type Token struct {
	ID       string
	Type     string
	ExpireAt time.Time
	Data     map[string]string
	mu       sync.RWMutex
	used     bool
}

func (t *Token) HasBeenUsed() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.used
}

func (t *Token) SetUsed() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.used = true
}

type AuthData struct {
	PrincipalID    string
	RoleName       string
	AuthDeadline   time.Time
	ExpireAt       time.Time
	RequestContext map[string]string
	token          *Token
}

func (a *AuthData) SetToken(token *Token) {
	a.token = token
}

func (a *AuthData) GetToken() *Token {
	return a.token
}

// ComputeTokenID generates a hash-based token ID from the token value.
// This enables safe logging while maintaining O(1) lookup performance.
// The token ID is deterministic - computing the hash of the same value
// will always produce the same ID, allowing efficient cache lookups.
func ComputeTokenID(tokenType, tokenValue string) string {
	h := sha256.New()
	h.Write([]byte(tokenValue))
	hash := hex.EncodeToString(h.Sum(nil))[:32]

	switch tokenType {
	case WARDEN_TOKEN:
		return "wtkn_" + hash
	case AWS_ACCESS_KEYS:
		return "awsk_" + hash
	case USER_PASS:
		return "usrp_" + hash
	default:
		return "unkn_" + hash
	}
}

// DetectTokenType determines the token type from the token value format
func DetectTokenType(tokenValue string) string {
	if strings.HasPrefix(tokenValue, "cws.") {
		return WARDEN_TOKEN
	} else if strings.HasPrefix(tokenValue, "AKIA") {
		return AWS_ACCESS_KEYS
	} else if strings.HasPrefix(tokenValue, "usr-") {
		return USER_PASS
	}
	// Fallback for legacy tokens without prefix
	return USER_PASS
}

type TokenStore interface {
	GenerateToken(tokenType string, authData *AuthData) (*Token, error)
	// ResolveToken validates and resolves a token value (not ID) to its principal and role.
	// The tokenValue parameter is what the client sends (e.g., in Authorization header).
	// Internally, this computes a hash-based ID for cache lookup.
	ResolveToken(ctx context.Context, tokenValue string, reqContext map[string]string) (string, string, error)
	// GetToken retrieves a token by its value (not ID).
	// The tokenValue parameter is what the client sends.
	// Internally, this computes a hash-based ID for cache lookup.
	GetToken(tokenValue string) *Token
	GetMetrics() map[string]int64
	Close()
}
