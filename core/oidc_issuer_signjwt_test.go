package core

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"io"
	"math/big"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSignJWT_LocalByteEquivalence proves that routing local in-process keys through
// the crypto.Signer interface (the new signJWT) is a pure refactor: it produces output
// byte-identical to the previous concrete-type path (rsa.SignPKCS1v15 for RS*, fixed-width
// R‖S for ES*). This is the guard that lets a remote KMS signer slot into the same path
// without changing what a local key emits.
func TestSignJWT_LocalByteEquivalence(t *testing.T) {
	claims := map[string]interface{}{
		"iss": "https://iss.example",
		"sub": "wid:n:m:p",
		"aud": "aud",
		"iat": 1700000000,
	}

	// RS256 is deterministic (PKCS#1 v1.5 over the digest), so the pre-refactor path and
	// the new interface path yield byte-identical signatures for the same signing input.
	t.Run("RS256_identical", func(t *testing.T) {
		sk := mustGen(t, oidcAlgRS256)
		header := map[string]string{"alg": oidcAlgRS256, "typ": "JWT", "kid": sk.kid}
		tok, err := signJWT(context.Background(), sk, header, claims)
		require.NoError(t, err)
		parts := strings.Split(tok, ".")
		require.Len(t, parts, 3)

		signingInput := parts[0] + "." + parts[1]
		digest := sha256.Sum256([]byte(signingInput))
		oldSig, err := rsa.SignPKCS1v15(rand.Reader, sk.key.(*rsa.PrivateKey), crypto.SHA256, digest[:])
		require.NoError(t, err)
		assert.Equal(t, base64.RawURLEncoding.EncodeToString(oldSig), parts[2],
			"RS256 signature must be byte-identical to the pre-refactor path")
	})

	// ECDSA signing is randomized, so we can't compare two independent signings. Instead
	// we prove the ASN.1→R‖S conversion is byte-identical to the old inline concat given
	// the SAME signature, and that a full signJWT ES256 token verifies.
	t.Run("ES256_conversion_identical_and_verifies", func(t *testing.T) {
		sk := mustGen(t, oidcAlgES256)
		key := sk.key.(*ecdsa.PrivateKey)

		digest := sha256.Sum256([]byte("a.b"))
		der, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
		require.NoError(t, err)

		jwsSig, err := ecSigASN1ToJWS(der, key.Curve)
		require.NoError(t, err)

		// Old path: parse (r,s) from the same DER and fixed-width concat.
		var parsed struct{ R, S *big.Int }
		_, err = asn1.Unmarshal(der, &parsed)
		require.NoError(t, err)
		n := ecByteLen(key.Curve)
		oldSig := append(ecCoord(parsed.R, n), ecCoord(parsed.S, n)...)
		assert.Equal(t, oldSig, jwsSig, "ES256 R‖S must match the pre-refactor concat")

		// Full signJWT output must verify against the public key.
		header := map[string]string{"alg": oidcAlgES256, "typ": "JWT", "kid": sk.kid}
		tok, err := signJWT(context.Background(), sk, header, claims)
		require.NoError(t, err)
		parts := strings.Split(tok, ".")
		require.Len(t, parts, 3)
		sig, err := base64.RawURLEncoding.DecodeString(parts[2])
		require.NoError(t, err)
		require.Len(t, sig, 2*n)
		r := new(big.Int).SetBytes(sig[:n])
		s := new(big.Int).SetBytes(sig[n:])
		d := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		assert.True(t, ecdsa.Verify(&key.PublicKey, d[:], r, s), "ES256 JWS signature must verify")
	})
}

// stubSigner is a crypto.Signer that records whether it was reached through a
// context-bound copy, proving signJWT threads the mint context to a KMS-style signer.
type stubSigner struct {
	inner    crypto.Signer
	ctx      context.Context
	withCtxN *int
}

func (s stubSigner) Public() crypto.PublicKey { return s.inner.Public() }
func (s stubSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.inner.Sign(r, digest, opts)
}
func (s stubSigner) WithContext(ctx context.Context) crypto.Signer {
	*s.withCtxN++
	s.ctx = ctx
	return s
}

// TestSignJWT_BindsContext proves signJWT calls WithContext on a signer that supports it,
// so a remote signer receives the request context (deadline/cancel) for the KMS round-trip.
func TestSignJWT_BindsContext(t *testing.T) {
	base := mustGen(t, oidcAlgRS256)
	n := 0
	sk := &signingKey{key: stubSigner{inner: base.key, withCtxN: &n}, alg: oidcAlgRS256, kid: base.kid}
	header := map[string]string{"alg": oidcAlgRS256, "typ": "JWT", "kid": sk.kid}
	_, err := signJWT(context.Background(), sk, header, map[string]interface{}{"aud": "a"})
	require.NoError(t, err)
	assert.Equal(t, 1, n, "signJWT must bind the context on a WithContext-capable signer")
}
