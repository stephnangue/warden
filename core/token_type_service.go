package core

import (
	"context"
	"strings"
	"time"

	"github.com/stephnangue/warden/helper"
)

// Service token values and IDs. A value is its prefix followed by
// serviceTokenRandomLen random characters; an ID is its prefix followed by the
// hash of the value (hashTokenID). Values take a "." after the product code
// "wd" and a letter naming the kind of token, IDs a "_".
const (
	serviceTokenValuePrefix = "wds."
	serviceTokenIDPrefix    = "wds_"
	serviceTokenRandomLen   = 64

	// Service tokens issued before the current prefixes. A presented value of
	// that format is still recognised and looked up under the ID it was stored
	// with, until it expires or is revoked; no token is issued in it any more.
	legacyServiceTokenValuePrefix = "cws."
	legacyServiceTokenIDPrefix    = "wtkn_"
)

// ServiceTokenType implements the bearer token Warden issues and persists. It
// carries its own policies; the root token is one.
type ServiceTokenType struct{}

func (t *ServiceTokenType) Metadata() TokenTypeMetadata {
	return TokenTypeMetadata{
		Name:              TypeServiceToken,
		IDPrefix:          serviceTokenIDPrefix,
		ValuePrefix:       serviceTokenValuePrefix,
		LegacyValuePrefix: legacyServiceTokenValuePrefix,
		Description:       "Warden service token: a persisted bearer token carrying its own policies",
		DefaultTTL:        1 * time.Hour,
	}
}

func (t *ServiceTokenType) Generate(_ context.Context, authData *AuthData, entry *TokenEntry) (map[string]string, error) {
	tokenValue := serviceTokenValuePrefix + helper.GenerateRandomString(serviceTokenRandomLen)

	entry.Data = map[string]string{
		"token": tokenValue,
	}

	return map[string]string{
		"token": tokenValue,
	}, nil
}

// ValidateValue reports whether tokenValue has the shape of a service token
// value, current or legacy.
func (t *ServiceTokenType) ValidateValue(tokenValue string) bool {
	const valueLen = len(serviceTokenValuePrefix) + serviceTokenRandomLen
	if len(tokenValue) != valueLen {
		return false
	}
	return strings.HasPrefix(tokenValue, serviceTokenValuePrefix) ||
		strings.HasPrefix(tokenValue, legacyServiceTokenValuePrefix)
}

// ComputeID returns the ID a service token value is stored under. A legacy
// value keeps the ID prefix it was stored with; any other value, including a
// custom dev-mode root token value, takes the current one.
func (t *ServiceTokenType) ComputeID(lookupValue string) string {
	prefix := serviceTokenIDPrefix
	if strings.HasPrefix(lookupValue, legacyServiceTokenValuePrefix) {
		prefix = legacyServiceTokenIDPrefix
	}
	return tokenID(prefix, lookupValue)
}

func (t *ServiceTokenType) LookupKey() string {
	return "token"
}

var _ TokenType = (*ServiceTokenType)(nil)
