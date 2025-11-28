package token

import (
	"context"
	"sync"
	"time"
)

const (
	USER_PASS       = "user_pass"
	AWS_ACCESS_KEYS = "aws_access_keys"
	WARDEN_TOKEN    = "warden_token"
)

type Token struct {
	ID           string
	Type         string
	ExpireAt     time.Time
	Data         map[string]string
	mu           sync.RWMutex
	used         bool
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
	PrincipalID         string
	RoleName            string
	AuthDeadline        time.Time
	ExpireAt            time.Time
	RequestContext      map[string]string
	token               *Token
}

func (a *AuthData) SetToken(token *Token) {
	a.token = token
}

func (a *AuthData) GetToken() *Token {
	return a.token
}

type TokenStore interface {
	GenerateToken(tokenType string, authData *AuthData) (*Token, error)
	ResolveToken(ctx context.Context, tokenID string, reqContext map[string]string) (string, string, error)
	GetToken(tokenID string) *Token
	GetMetrics() map[string]int64
	Close()
}