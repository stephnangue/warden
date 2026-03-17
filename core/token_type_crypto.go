package core

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	cryptoTokenEncryptionKey = "crypto-token"

	// CryptoTokenClaimsVersion is incremented when the claims schema changes.
	// Old tokens with a lower version will still decrypt but can be handled differently.
	CryptoTokenClaimsVersion = 1

	// MaxCryptoTokenPlaintextSize is the maximum allowed size of the JSON claims
	// before encryption. Prevents oversized tokens that would exceed HTTP header limits.
	// 6KB plaintext ≈ ~8KB base64 encoded, within typical HTTP header limits.
	MaxCryptoTokenPlaintextSize = 6 * 1024

	// MaxCryptoTokenValueSize is the maximum allowed size of the full token value
	// (prefix + base64 encoded ciphertext). Rejects oversized tokens early before decryption.
	MaxCryptoTokenValueSize = 10 * 1024
)

// CryptoTokenClaims holds the claims embedded in a crypto token's encrypted blob.
// Field names are abbreviated to minimize token size.
//
// Note: policies are baked in at issuance. If a role's policies change after
// the token is issued, the token still carries the old policies until it expires.
// This is an inherent trade-off of self-contained tokens (same as Vault batch tokens).
type CryptoTokenClaims struct {
	Version        int      `json:"v"`
	PrincipalID    string   `json:"pid"`
	RoleName       string   `json:"rn"`
	Policies       []string `json:"pol"`
	NamespaceID    string   `json:"nid"`
	NamespacePath  string   `json:"np"`
	ExpireAt       int64    `json:"exp"`
	CreatedAt      int64    `json:"iat"`
	CreatedByIP    string   `json:"cip"`
	CredentialSpec string   `json:"cs,omitempty"`
	Accessor       string   `json:"acc"`
}

// WardenCryptoTokenType implements a self-contained token type where the token
// value itself is a barrier-encrypted blob carrying all claims. No server-side
// storage or cache lookup is needed for validation — just decrypt and verify.
//
// Trade-offs vs reference tokens (warden_token):
//   - No individual revocation — tokens are valid until they expire
//   - Policies are frozen at issuance — role policy changes don't affect existing tokens
//   - Larger token size (~500-800 bytes vs 68 chars)
//   - Requires barrier to be unsealed for both generation and validation
type WardenCryptoTokenType struct {
	encryptor BarrierEncryptor
}

func (t *WardenCryptoTokenType) Metadata() TokenTypeMetadata {
	return TokenTypeMetadata{
		Name:        "warden_crypto_token",
		IDPrefix:    "wcrt_",
		ValuePrefix: "cwc.",
		Description: "Self-contained barrier-encrypted token",
		DefaultTTL:  1 * time.Hour,
	}
}

func (t *WardenCryptoTokenType) Generate(ctx context.Context, authData *AuthData, entry *TokenEntry) (map[string]string, error) {
	if authData == nil {
		return nil, errors.New("authData required for crypto token generation")
	}

	// Crypto tokens must have a finite expiration — they cannot be revoked
	if entry.ExpireAt.IsZero() {
		return nil, errors.New("crypto tokens require a finite expiration (cannot be non-expiring)")
	}

	claims := CryptoTokenClaims{
		Version:        CryptoTokenClaimsVersion,
		PrincipalID:    authData.PrincipalID,
		RoleName:       authData.RoleName,
		Policies:       authData.Policies,
		NamespaceID:    entry.NamespaceID,
		NamespacePath:  entry.NamespacePath,
		ExpireAt:       entry.ExpireAt.Unix(),
		CreatedAt:      entry.CreatedAt.Unix(),
		CreatedByIP:    authData.ClientIP,
		CredentialSpec: authData.CredentialSpec,
		Accessor:       entry.Accessor,
	}

	plaintext, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal crypto token claims: %w", err)
	}

	if len(plaintext) > MaxCryptoTokenPlaintextSize {
		return nil, fmt.Errorf("crypto token claims too large (%d bytes, max %d)", len(plaintext), MaxCryptoTokenPlaintextSize)
	}

	ciphertext, err := t.encryptor.Encrypt(ctx, cryptoTokenEncryptionKey, plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt crypto token: %w", err)
	}

	tokenValue := "cwc." + base64.RawURLEncoding.EncodeToString(ciphertext)

	entry.Data = map[string]string{
		"token": tokenValue,
	}

	return map[string]string{
		"token": tokenValue,
	}, nil
}

func (t *WardenCryptoTokenType) ValidateValue(tokenValue string) bool {
	if !strings.HasPrefix(tokenValue, "cwc.") {
		return false
	}
	if len(tokenValue) > MaxCryptoTokenValueSize {
		return false
	}
	payload := tokenValue[4:]
	_, err := base64.RawURLEncoding.DecodeString(payload)
	return err == nil && len(payload) > 0
}

func (t *WardenCryptoTokenType) ComputeID(lookupValue string) string {
	h := sha256.New()
	h.Write([]byte(lookupValue))
	hash := hex.EncodeToString(h.Sum(nil))[:32]
	return t.Metadata().IDPrefix + hash
}

func (t *WardenCryptoTokenType) LookupKey() string {
	return "token"
}

// DecryptToken decrypts a crypto token value and returns the embedded claims.
// Rejects tokens exceeding MaxCryptoTokenValueSize before attempting decryption.
func (t *WardenCryptoTokenType) DecryptToken(ctx context.Context, tokenValue string) (*CryptoTokenClaims, error) {
	if !strings.HasPrefix(tokenValue, "cwc.") {
		return nil, errors.New("invalid crypto token prefix")
	}

	if len(tokenValue) > MaxCryptoTokenValueSize {
		return nil, errors.New("crypto token value exceeds maximum size")
	}

	ciphertext, err := base64.RawURLEncoding.DecodeString(tokenValue[4:])
	if err != nil {
		return nil, fmt.Errorf("failed to decode crypto token: %w", err)
	}

	plaintext, err := t.encryptor.Decrypt(ctx, cryptoTokenEncryptionKey, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt crypto token: %w", err)
	}

	var claims CryptoTokenClaims
	if err := json.Unmarshal(plaintext, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal crypto token claims: %w", err)
	}

	return &claims, nil
}
