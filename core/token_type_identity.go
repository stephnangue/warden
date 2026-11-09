package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// identityTokenIDPrefix prefixes the ID of every identity token. No value
// prefix exists: an identity token has no value of its own.
const identityTokenIDPrefix = "wdi_"

// identityTokenLookupKey is the entry.Data key holding the hash an identity
// token's ID derives from.
const identityTokenLookupKey = "credential"

// IdentityTokenType implements the token of a caller admitted by a transparent
// auth method (jwt, kubernetes, cert, spiffe). It carries the verified identity
// and its facts, and no capabilities: a role grants them per request.
//
// The caller presents its own credential (a JWT, a service account JWT, a
// client certificate, an SVID) with every request; no value is handed out. The
// token lives in the cache only, one per (auth mount, credential): the hash of
// the mount accessor and the credential is both its lookup value and, hashed
// again, its ID. The mount accessor keeps two mounts presented the same
// credential apart, and keeps credentials of different formats apart too,
// since one mount admits one format (a spiffe mount's certificate fingerprint
// and JWT-SVID are disjoint inputs).
//
// How a credential is taken from a request is the auth method's business
// (logical.CredentialFormatProvider), not the token type's.
type IdentityTokenType struct{}

func (t *IdentityTokenType) Metadata() TokenTypeMetadata {
	return TokenTypeMetadata{
		Name:        TypeIdentityToken,
		IDPrefix:    identityTokenIDPrefix,
		Description: "Identity admitted by a transparent auth method",
		DefaultTTL:  1 * time.Hour,
	}
}

// Generate stores the (mount, credential) hash, never the raw credential:
// authData.TokenValue is the caller's JWT or certificate fingerprint. It
// returns entry.Data, from which the token's ID is computed; nothing in it is
// handed to the caller. It writes into entry.Data in place, which only an entry
// still being built allows: TestTokenEntrySharedFieldsNotMutatedInPlace (in
// logical) lists it as such a site.
func (t *IdentityTokenType) Generate(_ context.Context, authData *AuthData, entry *TokenEntry) (map[string]string, error) {
	if authData == nil || authData.TokenValue == "" {
		return entry.Data, nil
	}
	entry.Data[identityTokenLookupKey] = t.LookupValue(authData.TokenValue, authData.MountAccessor)
	return entry.Data, nil
}

// ValidateValue accepts anything: there is no bearer value to check, the
// credential is verified by its auth mount.
func (t *IdentityTokenType) ValidateValue(string) bool { return true }

func (t *IdentityTokenType) ComputeID(lookupValue string) string {
	return tokenID(identityTokenIDPrefix, lookupValue)
}

func (t *IdentityTokenType) LookupKey() string { return identityTokenLookupKey }

// LookupValue returns the SHA-256 of (mountAccessor, credential), which
// ComputeID hashes into the cache key. Satisfies TransparentTokenType.
func (t *IdentityTokenType) LookupValue(credential, mountAccessor string) string {
	h := sha256.Sum256([]byte(mountAccessor + ":" + credential))
	return hex.EncodeToString(h[:])
}

// IsTransparent always returns true; it opts the type into the transparent
// behaviours (cache-only persistence, the explicit-login guard, deterministic
// IDs).
func (t *IdentityTokenType) IsTransparent() bool { return true }

var _ TransparentTokenType = (*IdentityTokenType)(nil)

// identityTokenType is the one identity token type, stateless and shared: the
// token store registers it and transparent lookups hash with it.
var identityTokenType TransparentTokenType = &IdentityTokenType{}
