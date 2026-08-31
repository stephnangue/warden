package remotesign

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeKey is one transit key: a type plus a private key per version. The fake KMS
// holds the private key so signatures actually verify against the served public key.
type fakeKey struct {
	keyType    string
	exportable bool
	versions   []crypto.Signer // index 0 == version 1
}

// fakeTransit is a minimal transit engine over httptest: create/rotate/read/sign.
type fakeTransit struct {
	t        *testing.T
	keys     map[string]*fakeKey
	lastSign map[string]interface{} // captured params of the most recent sign call
}

func newFakeTransit(t *testing.T) *fakeTransit {
	return &fakeTransit{t: t, keys: map[string]*fakeKey{}}
}

func genKey(t *testing.T, keyType string) crypto.Signer {
	t.Helper()
	switch keyType {
	case "rsa-2048":
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		return k
	case "rsa-3072":
		k, err := rsa.GenerateKey(rand.Reader, 3072)
		require.NoError(t, err)
		return k
	case "ecdsa-p256":
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		return k
	case "ecdsa-p384":
		k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(t, err)
		return k
	}
	t.Fatalf("unknown key type %q", keyType)
	return nil
}

func pubPEM(t *testing.T, s crypto.Signer) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(s.Public())
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func (f *fakeTransit) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/v1/")
		writeJSON := func(v interface{}) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(v)
		}
		switch {
		case strings.HasSuffix(path, "/rotate"):
			name := strings.TrimSuffix(strings.TrimPrefix(path, "transit/keys/"), "/rotate")
			k := f.keys[name]
			require.NotNil(f.t, k, "rotate on missing key %q", name)
			k.versions = append(k.versions, genKey(f.t, k.keyType))
			writeJSON(map[string]interface{}{"data": map[string]interface{}{}})
		case strings.HasPrefix(path, "transit/keys/"):
			name := strings.TrimPrefix(path, "transit/keys/")
			if r.Method == http.MethodGet {
				k := f.keys[name]
				if k == nil {
					w.WriteHeader(http.StatusNotFound)
					writeJSON(map[string]interface{}{"errors": []string{"not found"}})
					return
				}
				keys := map[string]interface{}{}
				for i, v := range k.versions {
					keys[strconv.Itoa(i+1)] = map[string]interface{}{
						"public_key":    pubPEM(f.t, v),
						"creation_time": time.Now().UTC().Add(time.Duration(i) * time.Second).Format(time.RFC3339Nano),
					}
				}
				writeJSON(map[string]interface{}{"data": map[string]interface{}{
					"type":           k.keyType,
					"exportable":     k.exportable,
					"latest_version": len(k.versions),
					"keys":           keys,
				}})
				return
			}
			// create (idempotent upsert)
			var body map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if f.keys[name] == nil {
				kt, _ := body["type"].(string)
				f.keys[name] = &fakeKey{keyType: kt, versions: []crypto.Signer{genKey(f.t, kt)}}
			}
			writeJSON(map[string]interface{}{"data": map[string]interface{}{}})
		case strings.HasPrefix(path, "transit/sign/"):
			name := strings.TrimPrefix(path, "transit/sign/")
			var body map[string]interface{}
			require.NoError(f.t, json.NewDecoder(r.Body).Decode(&body))
			f.lastSign = body
			k := f.keys[name]
			require.NotNil(f.t, k, "sign on missing key %q", name)
			ver, _ := asInt(body["key_version"])
			require.True(f.t, ver >= 1 && ver <= len(k.versions), "bad key_version %d", ver)
			signer := k.versions[ver-1]
			input, _ := body["input"].(string)
			digest, err := base64.StdEncoding.DecodeString(input)
			require.NoError(f.t, err)
			var sig []byte
			switch key := signer.(type) {
			case *rsa.PrivateKey:
				h := crypto.SHA256
				if body["hash_algorithm"] == "sha2-384" {
					h = crypto.SHA384
				}
				sig, err = rsa.SignPKCS1v15(rand.Reader, key, h, digest)
			case *ecdsa.PrivateKey:
				sig, err = ecdsa.SignASN1(rand.Reader, key, digest)
			}
			require.NoError(f.t, err)
			writeJSON(map[string]interface{}{"data": map[string]interface{}{
				"signature":   "vault:v" + strconv.Itoa(ver) + ":" + base64.StdEncoding.EncodeToString(sig),
				"key_version": ver,
			}})
		default:
			w.WriteHeader(http.StatusNotFound)
			writeJSON(map[string]interface{}{"errors": []string{"unhandled: " + path}})
		}
	})
}

func newTestBackend(t *testing.T, f *fakeTransit) *TransitBackend {
	t.Helper()
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	b, err := NewTransitBackend(TransitConfig{
		Address:        srv.URL,
		Token:          "test-token",
		MountPath:      "transit",
		KeyNamePrefix:  "warden-oidc",
		RequestTimeout: 5 * time.Second,
		DisableRenewal: true,
	}, nil)
	require.NoError(t, err)
	t.Cleanup(b.Close)
	return b
}

func TestTransit_EnsureKey_and_Sign_RSA(t *testing.T) {
	f := newFakeTransit(t)
	b := newTestBackend(t, f)
	ctx := context.Background()

	info, err := b.EnsureKey(ctx, "RS256")
	require.NoError(t, err)
	assert.Equal(t, "warden-oidc-rs256", info.Ref.KeyName)
	assert.Equal(t, 1, info.Ref.Version)
	assert.Equal(t, "RS256", info.Ref.Alg)
	rsaPub, ok := info.Public.(*rsa.PublicKey)
	require.True(t, ok)

	digest := sha256.Sum256([]byte("signing.input"))
	sig, err := b.Sign(ctx, info.Ref, digest[:], crypto.SHA256)
	require.NoError(t, err)
	require.NoError(t, rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest[:], sig),
		"transit RSA signature must verify against the served public key")

	// Sign request must force pkcs1v15, prehashed, asn1 marshaling, and pin the version.
	assert.Equal(t, true, f.lastSign["prehashed"])
	assert.Equal(t, "pkcs1v15", f.lastSign["signature_algorithm"])
	assert.Equal(t, "asn1", f.lastSign["marshaling_algorithm"])
	assert.Equal(t, "sha2-256", f.lastSign["hash_algorithm"])
	v, _ := asInt(f.lastSign["key_version"])
	assert.Equal(t, 1, v)
}

func TestTransit_Sign_EC_ASN1(t *testing.T) {
	f := newFakeTransit(t)
	b := newTestBackend(t, f)
	ctx := context.Background()

	info, err := b.EnsureKey(ctx, "ES256")
	require.NoError(t, err)
	ecPub, ok := info.Public.(*ecdsa.PublicKey)
	require.True(t, ok)

	digest := sha256.Sum256([]byte("ec.signing.input"))
	sig, err := b.Sign(ctx, info.Ref, digest[:], crypto.SHA256)
	require.NoError(t, err)

	// The signer returns ASN.1 DER (crypto.Signer contract); it must verify.
	var parsed struct{ R, S *big.Int }
	_, err = asn1.Unmarshal(sig, &parsed)
	require.NoError(t, err)
	assert.True(t, ecdsa.Verify(ecPub, digest[:], parsed.R, parsed.S))

	// EC must NOT carry signature_algorithm (that is RSA-only).
	_, hasSigAlg := f.lastSign["signature_algorithm"]
	assert.False(t, hasSigAlg)
	assert.Equal(t, "asn1", f.lastSign["marshaling_algorithm"])
}

func TestTransit_NewVersion_PinsActiveVersion(t *testing.T) {
	f := newFakeTransit(t)
	b := newTestBackend(t, f)
	ctx := context.Background()

	active, err := b.EnsureKey(ctx, "RS256") // v1
	require.NoError(t, err)
	require.Equal(t, 1, active.Ref.Version)
	activePub := active.Public.(*rsa.PublicKey)

	next, err := b.NewVersion(ctx, "RS256") // v2 (latest)
	require.NoError(t, err)
	require.Equal(t, 2, next.Ref.Version)

	// Signing with the ACTIVE ref (v1) must pin v1 and verify against v1's key,
	// even though v2 is now latest — proving we never default to latest.
	digest := sha256.Sum256([]byte("pin"))
	sig, err := b.Sign(ctx, active.Ref, digest[:], crypto.SHA256)
	require.NoError(t, err)
	v, _ := asInt(f.lastSign["key_version"])
	assert.Equal(t, 1, v)
	require.NoError(t, rsa.VerifyPKCS1v15(activePub, crypto.SHA256, digest[:], sig))
	assert.NotEqual(t, activePub.N, next.Public.(*rsa.PublicKey).N, "v1 and v2 must be distinct keys")
}

func TestTransit_Exportable_HardError(t *testing.T) {
	f := newFakeTransit(t)
	f.keys["warden-oidc-rs256"] = &fakeKey{keyType: "rsa-2048", exportable: true, versions: []crypto.Signer{genKey(t, "rsa-2048")}}
	b := newTestBackend(t, f)

	_, err := b.EnsureKey(context.Background(), "RS256")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exportable")
}

func TestTransit_WrongType_HardError(t *testing.T) {
	f := newFakeTransit(t)
	// An RS256 key name backed by an EC key type — a misconfiguration that would
	// otherwise yield unverifiable JWTs.
	f.keys["warden-oidc-rs256"] = &fakeKey{keyType: "ecdsa-p256", versions: []crypto.Signer{genKey(t, "ecdsa-p256")}}
	b := newTestBackend(t, f)

	_, err := b.EnsureKey(context.Background(), "RS256")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected")
}

func TestDecodeTransitSignature(t *testing.T) {
	raw := []byte{0x01, 0x02, 0x03}
	enc := base64.StdEncoding.EncodeToString(raw)

	got, err := decodeTransitSignature("vault:v3:" + enc)
	require.NoError(t, err)
	assert.Equal(t, raw, got)

	// A custom version_template prefix (extra segments) still yields the payload,
	// since it is the final colon-delimited segment.
	got, err = decodeTransitSignature("my:org:v3:" + enc)
	require.NoError(t, err)
	assert.Equal(t, raw, got)

	// Empty payload must be rejected, not returned as a zero-length signature.
	_, err = decodeTransitSignature("vault:v1:")
	require.Error(t, err)

	_, err = decodeTransitSignature("garbage")
	require.Error(t, err)

	_, err = decodeTransitSignature("")
	require.Error(t, err)
}

func TestSigner_NilBackend_And_Context(t *testing.T) {
	// Verification-only signer (nil backend) fails closed on Sign but exposes Public.
	pub := genKey(t, "rsa-2048").Public()
	s := NewVerifyingSigner("transit", KeyRef{KeyName: "k", Version: 1, Alg: "RS256"}, pub)
	assert.False(t, s.CanSign())
	assert.Equal(t, pub, s.Public())
	_, err := s.Sign(rand.Reader, []byte("d"), crypto.SHA256)
	require.Error(t, err)

	// WithContext returns a distinct signer bound to ctx and does not mutate the original.
	ctx := context.Background()
	s2 := s.WithContext(ctx).(*Signer)
	assert.Nil(t, s.ctx)
	assert.NotNil(t, s2.ctx)
}

func TestTransit_Sign_AllAlgs(t *testing.T) {
	for _, alg := range []string{"RS256", "RS384", "ES256", "ES384"} {
		t.Run(alg, func(t *testing.T) {
			f := newFakeTransit(t)
			b := newTestBackend(t, f)
			ctx := context.Background()

			info, err := b.EnsureKey(ctx, alg)
			require.NoError(t, err)

			h := algParamsByAlg[alg].hash
			hh := h.New()
			hh.Write([]byte("payload for " + alg))
			digest := hh.Sum(nil)

			sig, err := b.Sign(ctx, info.Ref, digest, h)
			require.NoError(t, err)
			assert.Equal(t, true, f.lastSign["prehashed"], "prehashed must be set for all algs")

			switch pub := info.Public.(type) {
			case *rsa.PublicKey:
				require.NoError(t, rsa.VerifyPKCS1v15(pub, h, digest, sig))
			case *ecdsa.PublicKey:
				var parsed struct{ R, S *big.Int }
				_, err := asn1.Unmarshal(sig, &parsed)
				require.NoError(t, err)
				assert.True(t, ecdsa.Verify(pub, digest, parsed.R, parsed.S))
			default:
				t.Fatalf("unexpected public key type %T", pub)
			}
		})
	}
}

func TestTransit_Sign_Rejects(t *testing.T) {
	f := newFakeTransit(t)
	b := newTestBackend(t, f)
	ctx := context.Background()
	info, err := b.EnsureKey(ctx, "RS256")
	require.NoError(t, err)
	d := sha256.Sum256([]byte("x"))

	// RSA-PSS is not supported.
	_, err = b.Sign(ctx, info.Ref, d[:], &rsa.PSSOptions{Hash: crypto.SHA256})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PSS")

	// Wrong hash for the alg (SHA-384 digest for an RS256 key) must fail fast,
	// before any KMS round-trip, so it cannot yield an unverifiable signature.
	d384 := make([]byte, crypto.SHA384.Size())
	_, err = b.Sign(ctx, info.Ref, d384, crypto.SHA384)
	require.Error(t, err)

	// A zero/negative version resolves to "latest" server-side; reject it up front.
	_, err = b.Sign(ctx, KeyRef{KeyName: info.Ref.KeyName, Version: 0, Alg: "RS256"}, d[:], crypto.SHA256)
	require.Error(t, err)

	// Unknown alg.
	_, err = b.Sign(ctx, KeyRef{KeyName: "k", Version: 1, Alg: "HS256"}, d[:], crypto.SHA256)
	require.Error(t, err)
}

func TestParsePublicKeyPEM_Rejects(t *testing.T) {
	_, err := ParsePublicKeyPEM("")
	require.Error(t, err)
	_, err = ParsePublicKeyPEM("not pem at all")
	require.Error(t, err)
	_, err = ParsePublicKeyPEM("-----BEGIN PUBLIC KEY-----\nZm9v\n-----END PUBLIC KEY-----\n")
	require.Error(t, err, "valid PEM framing but garbage DER must fail")
}

func TestSigner_RoutesToBackend(t *testing.T) {
	f := newFakeTransit(t)
	b := newTestBackend(t, f)
	info, err := b.EnsureKey(context.Background(), "RS256")
	require.NoError(t, err)

	s := NewSigner(b, info.Ref, info.Public, 5*time.Second)
	require.True(t, s.CanSign())
	digest := sha256.Sum256([]byte("via signer"))
	sig, err := s.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	require.NoError(t, rsa.VerifyPKCS1v15(info.Public.(*rsa.PublicKey), crypto.SHA256, digest[:], sig))
}

// newClientTestBackend builds the client-injected backend the credential drivers use:
// an existing client, no key-name prefix, no renewal.
func newClientTestBackend(t *testing.T, f *fakeTransit) *TransitBackend {
	t.Helper()
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	cfg := api.DefaultConfig()
	cfg.Address = srv.URL
	c, err := api.NewClient(cfg)
	require.NoError(t, err)
	c.SetToken("test-token")
	b, err := NewTransitClientBackend(c, "transit", 5*time.Second, nil)
	require.NoError(t, err)
	t.Cleanup(b.Close)
	return b
}

// TestTransitClientBackend_NoRenewalRequest is the property that makes this constructor
// safe to call per request: it must not renew. The wrapped token is short-lived and
// owned by whoever obtained it, so a renew here would be a wasted round trip and would
// leave a watcher goroutine behind on every mint.
func TestTransitClientBackend_NoRenewalRequest(t *testing.T) {
	f := newFakeTransit(t)
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		f.handler().ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)

	cfg := api.DefaultConfig()
	cfg.Address = srv.URL
	c, err := api.NewClient(cfg)
	require.NoError(t, err)
	c.SetToken("test-token")

	b, err := NewTransitClientBackend(c, "transit", 5*time.Second, nil)
	require.NoError(t, err)
	assert.Nil(t, b.watcher, "no lifetime watcher, so no goroutine to leak")
	b.Close() // safe with a nil watcher
	for _, p := range paths {
		assert.NotContains(t, p, "auth/token/renew-self", "construction issues no renewal request")
	}
}

func TestTransitClientBackend_RequiresClientAndMount(t *testing.T) {
	_, err := NewTransitClientBackend(nil, "transit", 0, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client is required")

	c, err := api.NewClient(api.DefaultConfig())
	require.NoError(t, err)
	_, err = NewTransitClientBackend(c, "  ", 0, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mount_path is required")
}

// TestTransitClientBackend_PrefixlessOpsRefused: without a prefix there is no algorithm
// -> key-name mapping, so the deriving operations must say so rather than address a key
// literally named "-rs256".
func TestTransitClientBackend_PrefixlessOpsRefused(t *testing.T) {
	f := newFakeTransit(t)
	b := newClientTestBackend(t, f)

	_, err := b.EnsureKey(context.Background(), "RS256")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "explicit name")

	_, err = b.NewVersion(context.Background(), "RS256")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "explicit name")
}

// TestNamedKeyInfo_ResolvesLatestAndPinned: version 0 resolves to a concrete latest, and
// an explicit version is honoured. Resolving to a number is what lets a caller keep
// signing with the version it validated instead of whatever is newest later.
func TestNamedKeyInfo_ResolvesLatestAndPinned(t *testing.T) {
	f := newFakeTransit(t)
	f.keys["client-assertion"] = &fakeKey{keyType: "rsa-2048",
		versions: []crypto.Signer{genKey(t, "rsa-2048"), genKey(t, "rsa-2048")}}
	b := newClientTestBackend(t, f)

	latest, err := b.NamedKeyInfo(context.Background(), "client-assertion", "RS256", 0)
	require.NoError(t, err)
	assert.Equal(t, 2, latest.Ref.Version, "0 resolves to the concrete latest version")
	assert.Equal(t, "client-assertion", latest.Ref.KeyName)
	assert.NotNil(t, latest.Public)

	pinned, err := b.NamedKeyInfo(context.Background(), "client-assertion", "RS256", 1)
	require.NoError(t, err)
	assert.Equal(t, 1, pinned.Ref.Version)

	_, err = b.NamedKeyInfo(context.Background(), "client-assertion", "RS256", 99)
	require.Error(t, err, "a version that does not exist is refused at validation time")

	_, err = b.NamedKeyInfo(context.Background(), "", "RS256", 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "key name is required")
}

// TestNamedKeyInfo_RelaxedRSASizeButExactCurve: the operator provisions this key, so any
// RSA size may sign any RS* alg — refusing rsa-4096 for RS256 would reject a stronger
// key for no reason. Curves stay exact, since ES256 only verifies against P-256.
func TestNamedKeyInfo_RelaxedRSASizeButExactCurve(t *testing.T) {
	f := newFakeTransit(t)
	// A larger RSA key than the alg's nominal type, signing RS256.
	f.keys["big-rsa"] = &fakeKey{keyType: "rsa-3072", versions: []crypto.Signer{genKey(t, "rsa-3072")}}
	f.keys["p384"] = &fakeKey{keyType: "ecdsa-p384", versions: []crypto.Signer{genKey(t, "ecdsa-p384")}}
	f.keys["exportable"] = &fakeKey{keyType: "rsa-2048", exportable: true,
		versions: []crypto.Signer{genKey(t, "rsa-2048")}}
	b := newClientTestBackend(t, f)

	_, err := b.NamedKeyInfo(context.Background(), "big-rsa", "RS256", 0)
	require.NoError(t, err, "any RSA size signs any RS* alg")

	_, err = b.NamedKeyInfo(context.Background(), "p384", "ES256", 0)
	require.Error(t, err, "the curve must match the alg exactly")
	assert.Contains(t, err.Error(), "expected")

	_, err = b.NamedKeyInfo(context.Background(), "exportable", "RS256", 0)
	require.Error(t, err, "non-exportability is the premise of remote signing")
	assert.Contains(t, err.Error(), "exportable")
}
