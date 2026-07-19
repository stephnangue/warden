package drivers

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// signRS256JWT signs the given header and claims as a compact RS256 JWS. It is
// the general-purpose counterpart to the GitHub App JWT signer, used to build
// RFC 7523 client-assertion JWTs for private_key_jwt client authentication.
func signRS256JWT(key *rsa.PrivateKey, header map[string]string, claims map[string]interface{}) (string, error) {
	if key == nil {
		return "", fmt.Errorf("private key not configured")
	}
	if header == nil {
		header = map[string]string{}
	}
	header["alg"] = "RS256"
	if header["typ"] == "" {
		header["typ"] = "JWT"
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JWT header: %w", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JWT claims: %w", err)
	}

	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	h := rsaSHA256Hash()
	h.Write([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(nil, key, rsaSHA256HashType(), h.Sum(nil))
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

// newJTI returns a random token identifier for a client assertion.
func newJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
