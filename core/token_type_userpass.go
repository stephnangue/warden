package core

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/stephnangue/warden/helper"
)

// UserPassTokenType implements username/password token generation
type UserPassTokenType struct{}

func (t *UserPassTokenType) Metadata() TokenTypeMetadata {
	return TokenTypeMetadata{
		Name:        "user_pass",
		IDPrefix:    "usrp_",
		ValuePrefix: "usr-",
		Description: "Username/password authentication token",
		DefaultTTL:  1 * time.Hour,
	}
}

func (t *UserPassTokenType) Generate(authData *AuthData, entry *TokenEntry) (map[string]string, error) {
	username := "usr-" + helper.GenerateRandomString(26)
	password := helper.GenerateRandomString(40)

	entry.Data = map[string]string{
		"username": username,
		"password": password,
	}

	return map[string]string{
		"username": username,
		"password": password,
	}, nil
}

func (t *UserPassTokenType) ExtractValue(tokenValue string) string {
	// For user_pass, the username is the lookup value
	return tokenValue
}

func (t *UserPassTokenType) ValidateValue(tokenValue string) bool {
	return strings.HasPrefix(tokenValue, "usr-") && len(tokenValue) == 30
}

func (t *UserPassTokenType) ComputeID(lookupValue string) string {
	h := sha256.New()
	h.Write([]byte(lookupValue))
	hash := hex.EncodeToString(h.Sum(nil))[:32]
	return t.Metadata().IDPrefix + hash
}

func (t *UserPassTokenType) LookupKey() string {
	return "username"
}
