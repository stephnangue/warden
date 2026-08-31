package drivers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"fmt"

	"github.com/stephnangue/warden/internal/remotesign"
)

// signRS256JWT signs the given header and claims as a compact RS256 JWS with a key held
// in this process. It is the general-purpose counterpart to the GitHub App JWT signer,
// used to build RFC 7523 client-assertion JWTs for private_key_jwt client
// authentication.
//
// The encoding and signing are delegated so that a key held here and a key held
// elsewhere produce their assertions through one code path rather than two that can
// drift apart: an *rsa.PrivateKey is already a crypto.Signer whose Sign, handed a plain
// crypto.Hash, is PKCS#1 v1.5 — the same bytes this produced when it did the work
// inline. There is no context to bind, because signing with a local key makes no call.
func signRS256JWT(key *rsa.PrivateKey, header map[string]string, claims map[string]interface{}) (string, error) {
	if key == nil {
		return "", fmt.Errorf("private key not configured")
	}
	return remotesign.SignCompactJWS(context.Background(), key, "RS256", header, claims)
}

// newJTI returns a random token identifier for a client assertion.
func newJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
