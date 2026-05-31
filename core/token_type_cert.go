package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// CertRoleTokenType implements certificate-based token handling with role binding.
// This token type is used for implicit authentication, where clients
// present TLS client certificates and Warden performs implicit authentication.
// The (mountAccessor, fingerprint, role) tuple is used as the lookup value,
// and its hash becomes the token ID — mountAccessor prevents cache
// contamination across two cert mounts that share a role name and a cert.
type CertRoleTokenType struct{}

func (t *CertRoleTokenType) Metadata() TokenTypeMetadata {
	return TokenTypeMetadata{
		Name:           "cert_role",
		IDPrefix:       "cert_",
		ValuePrefix:    "", // No bearer prefix — certs are in TLS, not headers
		Description:    "TLS client certificate with role binding",
		DefaultTTL:     1 * time.Hour,
		AuthMethodType: "cert",
	}
}

func (t *CertRoleTokenType) Generate(_ context.Context, authData *AuthData, entry *TokenEntry) (map[string]string, error) {
	// For cert tokens, the certificate comes from the TLS connection.
	// authData.TokenValue contains the cert fingerprint (SHA-256 of DER bytes).
	//
	// We store a hash of the composite (mountAccessor, fingerprint, role)
	// value for:
	// - ID computation: ComputeID() uses this to derive the token ID
	// - Validation: LookupTransparentTokenWithRole compares hashes
	// The role + mountAccessor are included so:
	// - Same cert with different roles produces different tokens
	// - Same cert + role on two different mounts produces different tokens
	if authData == nil {
		return entry.Data, nil
	}

	fingerprint := authData.TokenValue
	if fingerprint == "" {
		return entry.Data, nil
	}

	entry.Data["cert_fingerprint"] = t.LookupValue(fingerprint, authData.MountAccessor, authData.RoleName)

	return entry.Data, nil
}

func (t *CertRoleTokenType) ValidateValue(tokenValue string) bool {
	// Cert tokens have no bearer value to validate — the cert is in the TLS connection
	return true
}

func (t *CertRoleTokenType) ComputeID(lookupValue string) string {
	h := sha256.New()
	h.Write([]byte(lookupValue))
	hash := hex.EncodeToString(h.Sum(nil))[:32]
	return t.Metadata().IDPrefix + hash
}

func (t *CertRoleTokenType) LookupKey() string {
	return "cert_fingerprint"
}

// LookupValue computes the SHA-256 hash of (mountAccessor, fingerprint, role)
// that ComputeID hashes into the byID-cache key. Including mountAccessor
// prevents cache contamination across two cert mounts with overlapping role
// names + the same client cert. Satisfies TransparentTokenType.
func (t *CertRoleTokenType) LookupValue(fingerprint, mountAccessor, role string) string {
	h := sha256.Sum256([]byte(mountAccessor + ":" + fingerprint + ":" + role))
	return hex.EncodeToString(h[:])
}

// IsTransparent always returns true; opts CertRoleTokenType into the
// transparent-auth family behaviors via the registry.
func (t *CertRoleTokenType) IsTransparent() bool { return true }

// CredentialFormat reports "cert" — TLS client certificates extracted
// from the TLS connection (or a forwarded-cert header).
func (t *CertRoleTokenType) CredentialFormat() string { return "cert" }

var _ TransparentTokenType = (*CertRoleTokenType)(nil)
