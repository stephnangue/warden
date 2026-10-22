package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

// JWTRoleTokenType implements the admission token of a JWT. This token type is
// used for implicit authentication, where clients send requests with JWTs
// directly and Warden admits them through a jwt auth mount. JWTs are
// recognized by their "eyJ" prefix (base64 encoded '{"'). The (mountAccessor,
// JWT) pair is used as the lookup value, and its hash becomes the token ID: one
// token per credential and mount, whatever role a request asks for. The role
// is granted per request.
type JWTRoleTokenType struct{}

func (t *JWTRoleTokenType) Metadata() TokenTypeMetadata {
	return TokenTypeMetadata{
		Name:           "jwt_role",
		IDPrefix:       "jwtr_",
		ValuePrefix:    "eyJ", // Base64 encoded '{"' - JWT header start
		Description:    "JWT bearer token admitted by a jwt auth mount",
		DefaultTTL:     1 * time.Hour,
		AuthMethodType: "jwt",
	}
}

func (t *JWTRoleTokenType) Generate(_ context.Context, authData *AuthData, entry *TokenEntry) (map[string]string, error) {
	// For JWT tokens, we don't generate - the JWT comes from an external IdP.
	// The JWT is passed via authData.TokenValue for implicit auth.
	//
	// We store a hash of the composite (mountAccessor, jwt) value (not the raw
	// JWT) for:
	// - Security: raw JWTs may contain sensitive claims
	// - ID computation: ComputeID() uses this to derive the token ID
	// The mountAccessor is included so the same JWT admitted by two mounts
	// produces two tokens.
	if authData == nil {
		return entry.Data, nil
	}

	jwt := authData.TokenValue
	if jwt == "" {
		return entry.Data, nil
	}

	entry.Data["jwt"] = t.LookupValue(jwt, authData.MountAccessor)

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

// LookupValue computes the SHA-256 hash of (mountAccessor, jwt) that ComputeID
// hashes into the byID-cache key. Including mountAccessor prevents cache
// contamination across two JWT mounts presented the same credential.
// Satisfies TransparentTokenType.
func (t *JWTRoleTokenType) LookupValue(jwt, mountAccessor string) string {
	h := sha256.Sum256([]byte(mountAccessor + ":" + jwt))
	return hex.EncodeToString(h[:])
}

// IsTransparent always returns true; opts JWTRoleTokenType into the
// transparent-auth family behaviors via the registry.
func (t *JWTRoleTokenType) IsTransparent() bool { return true }

// CredentialFormat reports "jwt" — generic JWT bearer tokens validated
// by JWKS/OIDC discovery. Kubernetes SA JWTs use the distinct
// "k8s_sa_jwt" subtype so the introspect aggregator can route them only
// to kubernetes mounts.
func (t *JWTRoleTokenType) CredentialFormat() string { return "jwt" }

var _ TransparentTokenType = (*JWTRoleTokenType)(nil)
