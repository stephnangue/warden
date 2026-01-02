package core

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/stephnangue/warden/helper"
)

// WardenTokenType implements Warden native token generation
type WardenTokenType struct{}

func (t *WardenTokenType) Metadata() TokenTypeMetadata {
	return TokenTypeMetadata{
		Name:        "warden_token",
		IDPrefix:    "wtkn_",
		ValuePrefix: "cws.",
		Description: "Warden native bearer token",
		DefaultTTL:  1 * time.Hour,
	}
}

func (t *WardenTokenType) Generate(authData *AuthData, entry *TokenEntry) (map[string]string, error) {
	tokenValue := "cws." + helper.GenerateRandomString(64)

	entry.Data = map[string]string{
		"token": tokenValue,
	}

	return map[string]string{
		"token": tokenValue,
	}, nil
}

func (t *WardenTokenType) ExtractValue(tokenValue string) string {
	// For Warden tokens, the full value is the lookup value
	return tokenValue
}

func (t *WardenTokenType) ValidateValue(tokenValue string) bool {
	return strings.HasPrefix(tokenValue, "cws.") && len(tokenValue) == 68
}

func (t *WardenTokenType) ComputeID(lookupValue string) string {
	h := sha256.New()
	h.Write([]byte(lookupValue))
	hash := hex.EncodeToString(h.Sum(nil))[:32]
	return t.Metadata().IDPrefix + hash
}

func (t *WardenTokenType) LookupKey() string {
	return "token"
}
