package core

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

// JWTRoleTokenType implements JWT-based token handling with role binding.
// This token type is used when providers operate in transparent mode, where clients
// send requests with JWTs directly and Warden performs implicit authentication.
// JWTs are recognized by their "eyJ" prefix (base64 encoded '{"').
// The JWT+role combination is used as the lookup value, and its hash becomes the token ID.
type JWTRoleTokenType struct{}

func (t *JWTRoleTokenType) Metadata() TokenTypeMetadata {
	return TokenTypeMetadata{
		Name:        "jwt_role",
		IDPrefix:    "jwtr_",
		ValuePrefix: "eyJ", // Base64 encoded '{"' - JWT header start
		Description: "JWT bearer token with role binding",
		DefaultTTL:  1 * time.Hour,
	}
}

func (t *JWTRoleTokenType) Generate(authData *AuthData, entry *TokenEntry) (map[string]string, error) {
	// For JWT tokens, we don't generate - the JWT comes from an external IdP.
	// The JWT is passed via authData.TokenValue for transparent mode.
	//
	// We store a hash of the composite "jwt:role" value (not the raw JWT) for:
	// - Security: raw JWTs may contain sensitive claims
	// - ID computation: ComputeID() uses this to derive the token ID
	// The role is included because:
	// - Same JWT with different roles should produce different tokens
	// - Each role may have different policies and credential specs
	if authData == nil {
		return entry.Data, nil
	}

	jwt := authData.TokenValue
	if jwt == "" {
		return entry.Data, nil
	}

	// Store hash of composite "jwt:role" value using ComputeData
	entry.Data["jwt"] = t.ComputeData(jwt, authData.RoleName)

	return entry.Data, nil
}

func (t *JWTRoleTokenType) ValidateValue(tokenValue string) bool {
	// JWT format: header.payload.signature (three base64 parts separated by dots)
	if !strings.HasPrefix(tokenValue, "eyJ") {
		return false
	}
	parts := strings.Split(tokenValue, ".")
	return len(parts) == 3 && len(parts[0]) > 0 && len(parts[1]) > 0 && len(parts[2]) > 0
}

func (t *JWTRoleTokenType) ComputeID(lookupValue string) string {
	// Hash the JWT to create a deterministic token ID
	h := sha256.New()
	h.Write([]byte(lookupValue))
	hash := hex.EncodeToString(h.Sum(nil))[:32]
	return t.Metadata().IDPrefix + hash
}

func (t *JWTRoleTokenType) LookupKey() string {
	return "jwt"
}

// ComputeData computes a SHA-256 hash of the composite "jwt:role" value.
// This hash is stored in entry.Data["jwt"] and used for both ID computation
// and validation. Hashing provides security (no raw JWT in storage) and
// ensures consistent ID computation across token creation and lookup.
func (t *JWTRoleTokenType) ComputeData(jwt, role string) string {
	lookupValue := jwt
	if role != "" {
		lookupValue = jwt + ":" + role
	}
	h := sha256.Sum256([]byte(lookupValue))
	return hex.EncodeToString(h[:])
}
