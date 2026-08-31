package remotesign

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignCompactJWS_RS256Verifies(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	token, err := SignCompactJWS(context.Background(), key, "RS256",
		map[string]string{"kid": "k1"}, map[string]interface{}{"iss": "me"})
	require.NoError(t, err)

	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	h := crypto.SHA256.New()
	h.Write([]byte(parts[0] + "." + parts[1]))
	require.NoError(t, rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, h.Sum(nil), sig))
}

// TestSignCompactJWS_ES256IsFixedWidthRS is the case a naive implementation gets wrong:
// crypto.Signer returns an ASN.1 SEQUENCE{r,s} for ECDSA, but JWS requires the
// fixed-width R‖S concatenation. Emitting the DER form produces well-formed bytes that
// no verifier accepts, so assert both the width and that ecdsa.Verify agrees.
func TestSignCompactJWS_ES256IsFixedWidthRS(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	token, err := SignCompactJWS(context.Background(), key, "ES256", nil, map[string]interface{}{"iss": "me"})
	require.NoError(t, err)

	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	require.Len(t, sig, 64, "ES256 signature is two 32-byte scalars, not DER")

	h := crypto.SHA256.New()
	h.Write([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	assert.True(t, ecdsa.Verify(&key.PublicKey, h.Sum(nil), r, s))
}

func TestSignCompactJWS_ES384IsFixedWidthRS(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	token, err := SignCompactJWS(context.Background(), key, "ES384", nil, map[string]interface{}{"iss": "me"})
	require.NoError(t, err)

	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	require.Len(t, sig, 96, "ES384 signature is two 48-byte scalars")
}

// TestSignCompactJWS_AlgHeaderComesFromTheAlgArgument: a header that disagreed with the
// key and hash actually used would be a signature no verifier can check, so the caller
// does not get to set alg.
func TestSignCompactJWS_AlgHeaderComesFromTheAlgArgument(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	token, err := SignCompactJWS(context.Background(), key, "RS256",
		map[string]string{"alg": "ES256", "typ": "custom+jwt"}, map[string]interface{}{"iss": "me"})
	require.NoError(t, err)

	headerJSON, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[0])
	require.NoError(t, err)
	var hdr map[string]string
	require.NoError(t, json.Unmarshal(headerJSON, &hdr))
	assert.Equal(t, "RS256", hdr["alg"], "alg is taken from the argument, not the caller's header")
	assert.Equal(t, "custom+jwt", hdr["typ"], "an explicit typ is preserved")
}

func TestSignCompactJWS_Rejects(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	_, err = SignCompactJWS(context.Background(), key, "PS256", nil, map[string]interface{}{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported signing algorithm")

	_, err = SignCompactJWS(context.Background(), nil, "RS256", nil, map[string]interface{}{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no signer")
}

// ctxSigner records whether the shared path bound the caller's context before signing,
// which is what bounds a remote signer's network call.
type ctxSigner struct {
	crypto.Signer
	bound    context.Context
	signedAt *context.Context // set to `bound` at Sign time, so the test sees what signed
}

func (s *ctxSigner) WithContext(ctx context.Context) crypto.Signer {
	cp := *s
	cp.bound = ctx
	return &cp
}

func (s *ctxSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	*s.signedAt = s.bound
	return s.Signer.Sign(r, digest, opts)
}

func TestSignCompactJWS_BindsContextWhenSignerSupportsIt(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	type ctxKey struct{}
	ctx := context.WithValue(context.Background(), ctxKey{}, "marker")
	var signedAt context.Context

	_, err = SignCompactJWS(ctx, &ctxSigner{Signer: key, signedAt: &signedAt}, "RS256", nil,
		map[string]interface{}{"iss": "me"})
	require.NoError(t, err)
	require.NotNil(t, signedAt, "a signer exposing WithContext is bound before signing")
	assert.Equal(t, "marker", signedAt.Value(ctxKey{}), "it receives the caller's own context")
}
