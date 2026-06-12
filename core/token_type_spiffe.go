package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// SpiffeRoleTokenType implements SPIFFE-based transparent token handling with
// role binding, for the unified spiffe auth method that accepts BOTH an
// X.509-SVID (TLS client certificate) and a JWT-SVID (bearer token) on one
// mount.
//
// It reports the virtual credential format "spiffe": the implicit-auth
// dispatcher resolves the actual wire credential per request and feeds either a
// certificate fingerprint (X.509-SVID) or the raw JWT (JWT-SVID) through the
// single lookup key. A fingerprint and a JWT are disjoint hash inputs, so the
// two credential kinds never collide in the byID cache even under one key.
//
// ValuePrefix is intentionally empty: a JWT-SVID is also "eyJ...", and jwt_role
// owns that prefix in the registry. A spiffe credential is always routed by
// mount type in the transparent dispatch, never by value-prefix detection.
type SpiffeRoleTokenType struct{}

func (t *SpiffeRoleTokenType) Metadata() TokenTypeMetadata {
	return TokenTypeMetadata{
		Name:           "spiffe_role",
		IDPrefix:       "spif_",
		ValuePrefix:    "",
		Description:    "SPIFFE X.509-SVID or JWT-SVID with role binding",
		DefaultTTL:     1 * time.Hour,
		AuthMethodType: "spiffe",
	}
}

func (t *SpiffeRoleTokenType) Generate(_ context.Context, authData *AuthData, entry *TokenEntry) (map[string]string, error) {
	// authData.TokenValue is the cert fingerprint (X.509-SVID login) or the raw
	// JWT (JWT-SVID login), depending on which login branch ran. Both collapse
	// through the same (mountAccessor, credential, role) hash; including
	// mountAccessor prevents cache contamination across two spiffe mounts that
	// share a role name and a credential.
	if authData == nil {
		return entry.Data, nil
	}
	cred := authData.TokenValue
	if cred == "" {
		return entry.Data, nil
	}
	entry.Data["spiffe_cred"] = t.LookupValue(cred, authData.MountAccessor, authData.RoleName)
	return entry.Data, nil
}

func (t *SpiffeRoleTokenType) ValidateValue(tokenValue string) bool {
	// No single bearer value to validate — the credential is an SVID (cert in TLS
	// or a JWT-SVID bearer), verified by the mount at login.
	return true
}

func (t *SpiffeRoleTokenType) ComputeID(lookupValue string) string {
	h := sha256.New()
	h.Write([]byte(lookupValue))
	hash := hex.EncodeToString(h.Sum(nil))[:32]
	return t.Metadata().IDPrefix + hash
}

func (t *SpiffeRoleTokenType) LookupKey() string {
	return "spiffe_cred"
}

// LookupValue computes the SHA-256 hash of (mountAccessor, credential, role)
// that ComputeID hashes into the byID-cache key. credential is the cert
// fingerprint or the raw JWT-SVID. Satisfies TransparentTokenType.
func (t *SpiffeRoleTokenType) LookupValue(credential, mountAccessor, role string) string {
	h := sha256.Sum256([]byte(mountAccessor + ":" + credential + ":" + role))
	return hex.EncodeToString(h[:])
}

// IsTransparent always returns true; opts SpiffeRoleTokenType into the
// transparent-auth family behaviors via the registry.
func (t *SpiffeRoleTokenType) IsTransparent() bool { return true }

// CredentialFormat reports the virtual format "spiffe" — resolved to an
// X.509-SVID or a JWT-SVID per request by the implicit-auth dispatcher.
func (t *SpiffeRoleTokenType) CredentialFormat() string { return "spiffe" }

var _ TransparentTokenType = (*SpiffeRoleTokenType)(nil)
