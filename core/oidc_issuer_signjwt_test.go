package core

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	_ "crypto/sha512" // registers SHA-384 for crypto.Hash.New()
	"encoding/base64"
	"encoding/json"
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

	// ECDSA signing is randomized, so two independent signings can't be compared. The
	// ASN.1→R‖S conversion itself is covered in remotesign; here a full signJWT ES256
	// token must be fixed-width R‖S and verify against the public key.
	t.Run("ES256_fixed_width_and_verifies", func(t *testing.T) {
		sk := mustGen(t, oidcAlgES256)
		key := sk.key.(*ecdsa.PrivateKey)
		n := ecByteLen(key.Curve)

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

// TestSignJWT_EveryIssuerAlgIsSignable walks oidcAlgSpecs by key, so an algorithm
// added to the issuer's table but not to remotesign's (which now does the signing)
// fails here rather than at mint time. TestOIDCIssuer_AlgSpec_Extensible mints a
// fixed list; this one follows the table.
func TestSignJWT_EveryIssuerAlgIsSignable(t *testing.T) {
	for alg, spec := range oidcAlgSpecs {
		t.Run(alg, func(t *testing.T) {
			sk := mustGen(t, alg)
			tok, err := signJWT(context.Background(), sk,
				map[string]string{"typ": "JWT", "kid": sk.kid}, map[string]interface{}{"aud": "a"})
			require.NoError(t, err)
			parts := strings.Split(tok, ".")
			require.Len(t, parts, 3)

			assert.Equal(t, alg, decodeJWSHeader(t, parts[0])["alg"])

			h := crypto.SHA256
			if strings.HasSuffix(alg, "384") {
				h = crypto.SHA384
			}
			hasher := h.New()
			hasher.Write([]byte(parts[0] + "." + parts[1]))
			digest := hasher.Sum(nil)
			sig, err := base64.RawURLEncoding.DecodeString(parts[2])
			require.NoError(t, err)

			if spec.curve != nil {
				n := ecByteLen(spec.curve)
				require.Len(t, sig, 2*n)
				pub := sk.key.Public().(*ecdsa.PublicKey)
				assert.True(t, ecdsa.Verify(pub, digest,
					new(big.Int).SetBytes(sig[:n]), new(big.Int).SetBytes(sig[n:])))
				return
			}
			assert.NoError(t, rsa.VerifyPKCS1v15(sk.key.Public().(*rsa.PublicKey), h, digest, sig))
		})
	}
}

// TestSignJWT_AlgHeaderComesFromTheKey proves a caller's header cannot name an alg
// other than the key's: the signed header carries sk.alg whatever was passed.
func TestSignJWT_AlgHeaderComesFromTheKey(t *testing.T) {
	sk := mustGen(t, oidcAlgRS256)
	tok, err := signJWT(context.Background(), sk,
		map[string]string{"alg": "none", "typ": "JWT", "kid": sk.kid}, map[string]interface{}{"aud": "a"})
	require.NoError(t, err)
	hdr := decodeJWSHeader(t, strings.Split(tok, ".")[0])
	assert.Equal(t, oidcAlgRS256, hdr["alg"])
	assert.Equal(t, sk.kid, hdr["kid"])
}

func decodeJWSHeader(t *testing.T, seg string) map[string]string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	require.NoError(t, err)
	var hdr map[string]string
	require.NoError(t, json.Unmarshal(raw, &hdr))
	return hdr
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
