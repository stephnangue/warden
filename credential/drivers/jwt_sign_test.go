package drivers

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSignRS256JWT_ByteIdenticalToInlineSigning pins the one property that matters when
// signing moves behind a shared helper: the bytes on the wire do not change. It rebuilds
// the assertion the way this function did when it signed inline — marshal, base64url,
// SHA-256, PKCS#1 v1.5 — and requires an exact match, so a future change to the shared
// path that alters header handling or encoding fails here rather than at an
// authorization server that rejects the assertion.
func TestSignRS256JWT_ByteIdenticalToInlineSigning(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	header := map[string]string{"kid": "key-1"}
	claims := map[string]interface{}{
		"iss": "client-abc",
		"sub": "client-abc",
		"aud": "https://idp.example.com/token",
		"jti": "fixed-jti",
		"iat": 1700000000,
		"exp": 1700000300,
	}

	got, err := signRS256JWT(key, header, claims)
	require.NoError(t, err)

	// The previous inline implementation, reproduced verbatim.
	expHeader := map[string]string{"kid": "key-1", "alg": "RS256", "typ": "JWT"}
	headerJSON, err := json.Marshal(expHeader)
	require.NoError(t, err)
	claimsJSON, err := json.Marshal(claims)
	require.NoError(t, err)
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON)
	h := rsaSHA256Hash()
	h.Write([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(nil, key, rsaSHA256HashType(), h.Sum(nil))
	require.NoError(t, err)
	want := signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)

	assert.Equal(t, want, got)
}

// TestSignRS256JWT_VerifiesAndSetsHeader covers the assertion an authorization server
// actually checks: a valid RS256 signature over the signing input, with alg and typ
// present and the caller's kid preserved.
func TestSignRS256JWT_VerifiesAndSetsHeader(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	token, err := signRS256JWT(key, map[string]string{"kid": "abc"}, map[string]interface{}{"iss": "c1"})
	require.NoError(t, err)

	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	var hdr map[string]string
	require.NoError(t, json.Unmarshal(headerJSON, &hdr))
	assert.Equal(t, "RS256", hdr["alg"])
	assert.Equal(t, "JWT", hdr["typ"])
	assert.Equal(t, "abc", hdr["kid"])

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	h := crypto.SHA256.New()
	h.Write([]byte(parts[0] + "." + parts[1]))
	assert.NoError(t, rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, h.Sum(nil), sig))
}

// TestSignRS256JWT_DoesNotMutateCallerHeader: the helper sets alg and typ on a copy. A
// caller reusing one header map across assertions would otherwise be handing in a map
// that already carries the previous call's values.
func TestSignRS256JWT_DoesNotMutateCallerHeader(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	header := map[string]string{"kid": "abc"}
	_, err = signRS256JWT(key, header, map[string]interface{}{"iss": "c1"})
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"kid": "abc"}, header)
}

// TestSignRS256JWT_NilKey fails closed rather than emitting an unsigned assertion.
func TestSignRS256JWT_NilKey(t *testing.T) {
	_, err := signRS256JWT(nil, nil, map[string]interface{}{"iss": "c1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "private key not configured")
}
