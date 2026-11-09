package drivers

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/internal/remotesign"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testClientCert is a self-signed client certificate and its key, as an operator
// would create them with openssl and paste them into a source.
type testClientCert struct {
	key     *rsa.PrivateKey
	leaf    *x509.Certificate
	certPEM string
	keyPEM  string
}

// newTestClientCert issues a self-signed RSA-2048 certificate valid from notBefore to
// notAfter.
func newTestClientCert(t *testing.T, notBefore, notAfter time.Time) testClientCert {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return issueTestClientCert(t, key, notBefore, notAfter)
}

// issueTestClientCert issues a self-signed certificate for an existing key.
func issueTestClientCert(t *testing.T, key *rsa.PrivateKey, notBefore, notAfter time.Time) testClientCert {
	t.Helper()
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "warden-test"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return testClientCert{
		key:     key,
		leaf:    leaf,
		certPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		keyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})),
	}
}

// validTestClientCert is a certificate valid for the next year.
func validTestClientCert(t *testing.T) testClientCert {
	t.Helper()
	return newTestClientCert(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
}

// x5tS256Of is the x5t#S256 of a certificate, computed independently of the code under test.
func x5tS256Of(leaf *x509.Certificate) string {
	sum := sha256.Sum256(leaf.Raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// verifyCertAssertion checks a certificate client assertion the way Entra ID does,
// strictly: PS256 with a salt exactly as long as the hash, x5t#S256 naming the
// certificate, and no kid. It returns the claims.
func verifyCertAssertion(t *testing.T, assertion string, leaf *x509.Certificate) map[string]interface{} {
	t.Helper()
	parts := strings.Split(assertion, ".")
	require.Len(t, parts, 3, "a compact JWS")

	hdrJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	var hdr map[string]interface{}
	require.NoError(t, json.Unmarshal(hdrJSON, &hdr))
	assert.Equal(t, "PS256", hdr["alg"])
	assert.Equal(t, "JWT", hdr["typ"])
	assert.Equal(t, x5tS256Of(leaf), hdr["x5t#S256"])
	assert.NotContains(t, hdr, "kid", "the certificate is named by x5t#S256 alone")

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	require.NoError(t, rsa.VerifyPSS(leaf.PublicKey.(*rsa.PublicKey), crypto.SHA256, digest[:], sig,
		&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}),
		"the assertion must verify as PS256 against the certificate's key")

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims map[string]interface{}
	require.NoError(t, json.Unmarshal(claimsJSON, &claims))
	nbf, _ := claims["nbf"].(float64)
	assert.LessOrEqual(t, nbf, float64(time.Now().Unix()), "nbf is not in the future")
	return claims
}

func TestParseClientCertificate(t *testing.T) {
	now := time.Now()
	c := validTestClientCert(t)

	parsed, err := parseClientCertificate(c.certPEM, now)
	require.NoError(t, err)
	assert.Equal(t, x5tS256Of(c.leaf), parsed.x5tS256)
	s1 := sha1.Sum(c.leaf.Raw)
	assert.Equal(t, strings.ToUpper(hex.EncodeToString(s1[:])), parsed.sha1Hex)
	require.NoError(t, parsed.matchesPublicKey(&c.key.PublicKey))

	other := validTestClientCert(t)
	err = parsed.matchesPublicKey(&other.key.PublicKey)
	require.Error(t, err)
	assert.Contains(t, err.Error(), parsed.x5tS256)

	assert.False(t, parsed.expiresWithin(now, 30*24*time.Hour))
	assert.True(t, parsed.expiresWithin(now, 400*24*time.Hour))
}

func TestDescribeCertificate(t *testing.T) {
	now := time.Now()
	c := newTestClientCert(t, now.Add(-time.Hour), now.Add(36*time.Hour))
	info := DescribeCertificate(c.certPEM, now)
	require.NotNil(t, info)
	assert.Equal(t, "CN=warden-test", info["subject"])
	assert.Equal(t, 1, info["days_remaining"])
	assert.Equal(t, x5tS256Of(c.leaf), info["x5t_s256"])
	assert.Equal(t, certificateSHA1Thumbprint(c.certPEM), info["thumbprint_sha1"])

	// An expired certificate is described, reading negative from its first hour on.
	expired := newTestClientCert(t, now.Add(-48*time.Hour), now.Add(-time.Hour))
	assert.Equal(t, -1, DescribeCertificate(expired.certPEM, now)["days_remaining"])

	assert.Nil(t, DescribeCertificate("", now))
	assert.Nil(t, DescribeCertificate(c.keyPEM, now))
}

func TestParseClientCertificate_Refusals(t *testing.T) {
	now := time.Now()
	valid := validTestClientCert(t)
	expired := newTestClientCert(t, now.Add(-48*time.Hour), now.Add(-time.Hour))
	future := newTestClientCert(t, now.Add(time.Hour), now.Add(48*time.Hour))
	nearFuture := newTestClientCert(t, now.Add(time.Minute), now.Add(48*time.Hour))

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	ecDER, err := x509.CreateCertificate(rand.Reader, ecTmpl, ecTmpl, &ecKey.PublicKey, ecKey)
	require.NoError(t, err)
	ecPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ecDER}))

	small, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	smallCert := issueTestClientCert(t, small, now.Add(-time.Hour), now.Add(time.Hour))

	for name, tc := range map[string]struct{ pem, want string }{
		"empty":         {"", "no PEM block"},
		"a key":         {valid.keyPEM, `"PRIVATE KEY"`},
		"a chain":       {valid.certPEM + valid.certPEM, "not a chain"},
		"garbage":       {"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", "failed to parse"},
		"expired":       {expired.certPEM, "expired at"},
		"not yet valid": {future.certPEM, "not valid until"},
		"EC key":        {ecPEM, "RSA key is required"},
		"short RSA key": {smallCert.certPEM, "at least 2048"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parseClientCertificate(tc.pem, now)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}

	// A certificate whose validity starts within the skew is accepted: the host that
	// issued it may simply run a little ahead.
	_, err = parseClientCertificate(nearFuture.certPEM, now)
	require.NoError(t, err)
}

func TestSignCertClientAssertionLocal(t *testing.T) {
	c := validTestClientCert(t)
	parsed, err := parseClientCertificate(c.certPEM, time.Now())
	require.NoError(t, err)

	claims, err := certClientAssertionClaims("client-1", "https://login.example/tenant/oauth2/v2.0/token")
	require.NoError(t, err)
	assertion, err := signCertClientAssertionLocal(c.key, parsed.x5tS256, claims)
	require.NoError(t, err)

	got := verifyCertAssertion(t, assertion, c.leaf)
	assert.Equal(t, "client-1", got["iss"])
	assert.Equal(t, "client-1", got["sub"])
	assert.Equal(t, "https://login.example/tenant/oauth2/v2.0/token", got["aud"])
	assert.NotEmpty(t, got["jti"])
	assert.Equal(t, got["iat"], got["nbf"], "nbf is the time of issue")
	assert.InDelta(t, clientAssertionTTL.Seconds(), got["exp"].(float64)-got["iat"].(float64), 1)

	// The shared claims other drivers send are untouched: no nbf.
	plain, err := clientAssertionClaims("client-1", "aud")
	require.NoError(t, err)
	assert.NotContains(t, plain, "nbf")
}

func TestSignCertClientAssertionWithCapability_RefusesOtherAlgs(t *testing.T) {
	payload := map[string]string{}
	for k, v := range remotesign.EncodeTransitCapability(remotesign.TransitCapability{
		Token: "t", Address: "https://kms.example", Mount: "transit",
		Ref:       remotesign.KeyRef{KeyName: "k", Version: "1", Alg: "RS256"},
		ExpiresAt: time.Now().Add(time.Hour),
	}) {
		payload[k] = v.(string)
	}
	c, err := remotesign.DecodeCapability(payload)
	require.NoError(t, err)

	// No signer is needed: the alg is refused before the store is asked.
	_, err = signCertClientAssertionWithCapability(context.Background(), nil, c, "x5t", map[string]interface{}{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signing_alg=PS256")
	assert.NotErrorIs(t, err, credential.ErrChainedSecretRejected, "a misconfigured signer spec is not cured by a refetch")
}
