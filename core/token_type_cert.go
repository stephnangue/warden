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
// The cert fingerprint + role combination is used as the lookup value, and its hash
// becomes the token ID.
type CertRoleTokenType struct{}

func (t *CertRoleTokenType) Metadata() TokenTypeMetadata {
	return TokenTypeMetadata{
		Name:        "cert_role",
		IDPrefix:    "cert_",
		ValuePrefix: "", // No bearer prefix — certs are in TLS, not headers
		Description: "TLS client certificate with role binding",
		DefaultTTL:  1 * time.Hour,
	}
}

func (t *CertRoleTokenType) Generate(_ context.Context, authData *AuthData, entry *TokenEntry) (map[string]string, error) {
	// For cert tokens, the certificate comes from the TLS connection.
	// authData.TokenValue contains the cert fingerprint (SHA-256 of DER bytes).
	//
	// We store a hash of the composite "fingerprint:role" value for:
	// - ID computation: ComputeID() uses this to derive the token ID
	// - Validation: LookupCertTokenWithRole compares hashes
	// The role is included because:
	// - Same cert with different roles should produce different tokens
	// - Each role may have different policies and credential specs
	if authData == nil {
		return entry.Data, nil
	}

	fingerprint := authData.TokenValue
	if fingerprint == "" {
		return entry.Data, nil
	}

	// Store hash of composite "fingerprint:role" value
	entry.Data["cert_fingerprint"] = t.ComputeData(fingerprint, authData.RoleName)

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

// ComputeData computes a SHA-256 hash of the composite "fingerprint:role" value.
// This hash is stored in entry.Data["cert_fingerprint"] and used for both ID
// computation and validation.
func (t *CertRoleTokenType) ComputeData(fingerprint, role string) string {
	lookupValue := fingerprint
	if role != "" {
		lookupValue = fingerprint + ":" + role
	}
	h := sha256.Sum256([]byte(lookupValue))
	return hex.EncodeToString(h[:])
}
