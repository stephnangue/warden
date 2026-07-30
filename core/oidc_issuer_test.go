package core

import (
	"context"
	"crypto"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hashicorp/cap/jwt"
	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// keyEqual reports whether two signing keys' private halves are equal. Both
// *rsa.PrivateKey and *ecdsa.PrivateKey implement Equal(crypto.PrivateKey).
func keyEqual(a, b crypto.Signer) bool {
	e, ok := a.(interface{ Equal(crypto.PrivateKey) bool })
	return ok && e.Equal(b)
}

// rs256Keyset wraps a single RS256 keyset as the per-algorithm map the issuer uses.
func rs256Keyset(active, next *signingKey, retired []*signingKey) map[string]*algKeyset {
	return map[string]*algKeyset{oidcAlgRS256: {active: active, next: next, retired: retired}}
}

// rs256Keys returns an issuer's RS256 active, next, and retired keys.
func rs256Keys(iss *OIDCIssuer) (active, next *signingKey, retired []*signingKey) {
	ks := iss.Keys()[oidcAlgRS256]
	if ks == nil {
		return nil, nil, nil
	}
	return ks.active, ks.next, ks.retired
}

// loadRS256 loads the persisted keyset and returns the RS256 keyset's active,
// next, and retired keys (all nil when none is persisted).
func loadRS256(ctx context.Context, storage sdklogical.Storage) (active, next *signingKey, retired []*signingKey, err error) {
	keysets, err := loadKeySet(ctx, storage)
	if err != nil {
		return nil, nil, nil, err
	}
	ks := keysets[oidcAlgRS256]
	if ks == nil {
		return nil, nil, nil, nil
	}
	return ks.active, ks.next, ks.retired, nil
}

// persistRS256 persists a single RS256 keyset (the pre-map helper shape).
func persistRS256(ctx context.Context, storage sdklogical.Storage, active, next *signingKey, retired []*signingKey) error {
	return persistKeySet(ctx, storage, rs256Keyset(active, next, retired))
}

// mustGen generates a signing key for alg or fails the test.
func mustGen(t *testing.T, alg string) *signingKey {
	t.Helper()
	k, err := generateSigningKey(alg)
	if err != nil {
		t.Fatalf("generateSigningKey(%s): %v", alg, err)
	}
	return k
}

// newReadyIssuer returns a fully-ready issuer: an active key for EVERY supported
// algorithm (so Ready() is true). RS256-focused tests reach the RS256 key via
// rs256Keys; the extra ES256 key just rides along in the JWKS.
func newReadyIssuer(t *testing.T, issuerURL string) *OIDCIssuer {
	t.Helper()
	iss := NewOIDCIssuer(issuerURL)
	iss.RestoreKeys(map[string]*algKeyset{
		oidcAlgRS256: {active: mustGen(t, oidcAlgRS256)},
		oidcAlgES256: {active: mustGen(t, oidcAlgES256)},
	})
	return iss
}

// newReadyIssuerWithNext returns a fully-ready issuer with an active + pre-published
// next key for every supported algorithm, plus the RS256 active/next, for
// rotation-shaped tests.
func newReadyIssuerWithNext(t *testing.T, issuerURL string) (iss *OIDCIssuer, active, next *signingKey) {
	t.Helper()
	iss = NewOIDCIssuer(issuerURL)
	active, next = mustGen(t, oidcAlgRS256), mustGen(t, oidcAlgRS256)
	iss.RestoreKeys(map[string]*algKeyset{
		oidcAlgRS256: {active: active, next: next},
		oidcAlgES256: {active: mustGen(t, oidcAlgES256), next: mustGen(t, oidcAlgES256)},
	})
	return iss, active, next
}

// serveJWKS stands up an httptest server returning the issuer's JWKS, so a real
// cap/jwt validator can fetch and verify against it exactly like an upstream STS.
func serveJWKS(t *testing.T, iss *OIDCIssuer) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		body, err := iss.JWKS()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestOIDCIssuer_Mint_VerifiesAgainstJWKS is the interoperability proof: a minted
// assertion validates against the published JWKS using the same verifier library
// (hashicorp/cap/jwt) an upstream would use, and carries the expected claims.
func TestOIDCIssuer_Mint_VerifiesAgainstJWKS(t *testing.T) {
	const issuerURL = "https://warden-oidc.example.com"
	iss := newReadyIssuer(t, issuerURL)
	jwks := serveJWKS(t, iss)

	te := &logical.TokenEntry{
		PrincipalID:   "spiffe://acme.internal/agent/refund-bot",
		RoleName:      "payments-agent",
		NamespaceID:   "ns-1234",
		NamespacePath: "/acme/prod/",
		MountAccessor: "auth_jwt_abc",
	}
	const audience = "https://sso.acme.internal/realms/acme"

	token, err := iss.MintIdentityAssertion(te, audience, 5*time.Minute, nil, oidcAlgRS256)
	if err != nil {
		t.Fatalf("MintIdentityAssertion: %v", err)
	}

	ctx := context.Background()
	keySet, err := jwt.NewJSONWebKeySet(ctx, jwks.URL, "")
	if err != nil {
		t.Fatalf("NewJSONWebKeySet: %v", err)
	}
	validator, err := jwt.NewValidator(keySet)
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}

	claims, err := validator.Validate(ctx, token, jwt.Expected{
		Issuer:            issuerURL,
		Audiences:         []string{audience},
		SigningAlgorithms: []jwt.Alg{jwt.RS256},
	})
	if err != nil {
		t.Fatalf("validate minted assertion against JWKS: %v", err)
	}

	if got := claims["sub"]; got != "wid:ns-1234:auth_jwt_abc:spiffe://acme.internal/agent/refund-bot" {
		t.Errorf("sub = %v", got)
	}
	if got := claims["warden_role"]; got != "payments-agent" {
		t.Errorf("warden_role = %v", got)
	}
	if got := claims["warden_namespace"]; got != "/acme/prod/" {
		t.Errorf("warden_namespace = %v", got)
	}
	if got := claims["warden_auth_mount"]; got != "auth_jwt_abc" {
		t.Errorf("warden_auth_mount = %v", got)
	}
}

// TestOIDCIssuer_Mint_WardenMetadataClaim verifies that projected metadata rides
// under a single nested "warden_metadata" claim, verifiable against the JWKS, and
// that an empty projection emits no such claim (byte-for-byte the prior behavior).
func TestOIDCIssuer_Mint_WardenMetadataClaim(t *testing.T) {
	const issuerURL = "https://warden-oidc.example.com"
	iss := newReadyIssuer(t, issuerURL)
	jwks := serveJWKS(t, iss)
	te := &logical.TokenEntry{PrincipalID: "p", RoleName: "r", NamespaceID: "n", MountAccessor: "m"}
	const audience = "sts.amazonaws.com"

	ctx := context.Background()
	keySet, err := jwt.NewJSONWebKeySet(ctx, jwks.URL, "")
	require.NoError(t, err)
	validator, err := jwt.NewValidator(keySet)
	require.NoError(t, err)
	expected := jwt.Expected{Issuer: issuerURL, Audiences: []string{audience}, SigningAlgorithms: []jwt.Alg{jwt.RS256}}

	// With metadata: exactly the passed keys appear, nested under warden_metadata.
	withMeta, err := iss.MintIdentityAssertion(te, audience, 5*time.Minute, map[string]string{"team": "payments", "env": "prod"}, oidcAlgRS256)
	require.NoError(t, err)
	claims, err := validator.Validate(ctx, withMeta, expected)
	require.NoError(t, err)
	md, ok := claims["warden_metadata"].(map[string]interface{})
	require.True(t, ok, "warden_metadata claim missing or wrong type: %v", claims["warden_metadata"])
	assert.Equal(t, "payments", md["team"])
	assert.Equal(t, "prod", md["env"])
	assert.Len(t, md, 2)

	// Empty projection: no warden_metadata claim at all.
	for _, empty := range []map[string]string{nil, {}} {
		noMeta, err := iss.MintIdentityAssertion(te, audience, 5*time.Minute, empty, oidcAlgRS256)
		require.NoError(t, err)
		claims, err := validator.Validate(ctx, noMeta, expected)
		require.NoError(t, err)
		_, present := claims["warden_metadata"]
		assert.False(t, present, "warden_metadata must be absent for empty projection %v", empty)
	}
}

// TestOIDCIssuer_ES256_MintAndJWKS proves the ES256 path end-to-end: an ES256 key
// mints an assertion that verifies against the served JWKS via cap/jwt (which
// rejects a DER-encoded signature, so this guards the raw R‖S JWS encoding), and
// the JWKS renders a proper EC JWK.
func TestOIDCIssuer_ES256_MintAndJWKS(t *testing.T) {
	const issuerURL = "https://warden-oidc.example.com"
	iss := NewOIDCIssuer(issuerURL)
	key, err := generateSigningKey(oidcAlgES256)
	require.NoError(t, err)
	iss.RestoreKeys(map[string]*algKeyset{oidcAlgES256: {active: key}})
	jwks := serveJWKS(t, iss)

	te := &logical.TokenEntry{PrincipalID: "p", RoleName: "r", NamespaceID: "n", MountAccessor: "m"}
	const audience = "sts.amazonaws.com"
	token, err := iss.MintIdentityAssertion(te, audience, 5*time.Minute, nil, oidcAlgES256)
	require.NoError(t, err)

	ctx := context.Background()
	keySet, err := jwt.NewJSONWebKeySet(ctx, jwks.URL, "")
	require.NoError(t, err)
	validator, err := jwt.NewValidator(keySet)
	require.NoError(t, err)
	// Allow ONLY ES256: verification passing proves the header alg is ES256 and the
	// signature is a valid raw-R‖S ES256 signature (a DER signature would fail here).
	claims, err := validator.Validate(ctx, token, jwt.Expected{
		Issuer: issuerURL, Audiences: []string{audience}, SigningAlgorithms: []jwt.Alg{jwt.ES256},
	})
	require.NoError(t, err)
	assert.Equal(t, wardenSubject(te), claims["sub"])

	// The JWKS entry is a P-256 EC JWK (crv/x/y, no RSA n/e).
	body, err := iss.JWKS()
	require.NoError(t, err)
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(body, &set))
	require.Len(t, set.Keys, 1)
	k := set.Keys[0]
	assert.Equal(t, "EC", k["kty"])
	assert.Equal(t, "P-256", k["crv"])
	assert.Equal(t, "ES256", k["alg"])
	assert.Equal(t, key.kid, k["kid"])
	assert.NotEmpty(t, k["x"])
	assert.NotEmpty(t, k["y"])
	_, hasN := k["n"]
	assert.False(t, hasN, "EC JWK must not carry RSA n")

	// Discovery advertises the active key's algorithm.
	disc, err := iss.DiscoveryDocument(jwks.URL)
	require.NoError(t, err)
	var d struct {
		Algs []string `json:"id_token_signing_alg_values_supported"`
	}
	require.NoError(t, json.Unmarshal(disc, &d))
	assert.Equal(t, []string{"ES256"}, d.Algs)
}

// TestOIDCIssuer_ES256_StorageRoundTrip verifies an ES256 key survives the
// polymorphic PKCS#8 storage path (alg preserved, key reloads).
func TestOIDCIssuer_ES256_StorageRoundTrip(t *testing.T) {
	orig, err := generateSigningKey(oidcAlgES256)
	require.NoError(t, err)

	stored, err := toStored(orig)
	require.NoError(t, err)
	assert.Equal(t, "ES256", stored.Alg)

	loaded, err := fromStored(stored)
	require.NoError(t, err)
	assert.Equal(t, orig.kid, loaded.kid)
	assert.Equal(t, "ES256", loaded.alg)
	assert.True(t, keyEqual(loaded.key, orig.key), "reloaded ES256 key must equal the original")
}

// TestOIDCIssuer_KeyStorage_RejectsOldVersion ensures an unrecognized keyset
// version fails loudly rather than being silently regenerated over (which would
// destroy an existing keyset and orphan in-flight assertions).
func TestOIDCIssuer_KeyStorage_RejectsOldVersion(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()
	ctx := context.Background()
	storage := NewBarrierView(core.barrier, oidcIssuerStorePrefix)

	require.NoError(t, storage.Put(ctx, &sdklogical.StorageEntry{
		Key: oidcKeySetPath, Value: []byte(`{"version":2,"active":{}}`),
	}))
	_, err := loadKeySet(ctx, storage)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported keyset version 2")
}

// TestOIDCIssuer_JWKS_EmptyIsArray ensures the JWKS renders keys as [] (a valid
// RFC 7517 array), not null, when the issuer holds no keys.
func TestOIDCIssuer_JWKS_EmptyIsArray(t *testing.T) {
	body, err := NewOIDCIssuer("https://iss.example").JWKS()
	require.NoError(t, err)
	assert.JSONEq(t, `{"keys":[]}`, string(body))
}

// TestOIDCIssuer_FailClosed covers the cases where minting must refuse.
func TestOIDCIssuer_FailClosed(t *testing.T) {
	te := &logical.TokenEntry{PrincipalID: "p", NamespaceID: "n", MountAccessor: "m"}

	// Not ready: no active key.
	notReady := NewOIDCIssuer("https://iss.example")
	if notReady.Ready() {
		t.Fatal("issuer with no key must not be ready")
	}
	if _, err := notReady.MintIdentityAssertion(te, "aud", time.Minute, nil, oidcAlgRS256); err == nil {
		t.Error("mint must fail closed when no active key is installed")
	}

	ready := newReadyIssuer(t, "https://iss.example")
	if _, err := ready.MintIdentityAssertion(te, "", time.Minute, nil, oidcAlgRS256); err == nil {
		t.Error("mint must fail closed on empty audience")
	}
	if _, err := ready.MintIdentityAssertion(nil, "aud", time.Minute, nil, oidcAlgRS256); err == nil {
		t.Error("mint must fail closed on nil token entry")
	}
	if _, err := ready.MintIdentityAssertion(&logical.TokenEntry{}, "aud", time.Minute, nil, oidcAlgRS256); err == nil {
		t.Error("mint must fail closed when the principal is empty")
	}

	// A next key alone (no active) is not ready — the next key never signs until
	// it is promoted to active.
	// RS256 has a next key but no active (ES256 is complete, so the not-ready state
	// is caused specifically by RS256 lacking an active key, not by a missing alg).
	nextOnly := NewOIDCIssuer("https://iss.example")
	nextOnly.RestoreKeys(map[string]*algKeyset{
		oidcAlgRS256: {next: mustGen(t, oidcAlgRS256)},
		oidcAlgES256: {active: mustGen(t, oidcAlgES256), next: mustGen(t, oidcAlgES256)},
	})
	if nextOnly.Ready() {
		t.Error("an issuer with only a next key for an alg must not be ready")
	}
	if _, err := nextOnly.MintIdentityAssertion(te, "aud", time.Minute, nil, oidcAlgRS256); err == nil {
		t.Error("mint must fail closed when the alg has only a next key")
	}
}

// TestOIDCIssuer_KeyStorage_RoundTrip verifies the signing key survives a
// persist/load cycle through a barrier view (so a promoted standby can reload the
// key an active node generated) and still signs a verifiable assertion.
func TestOIDCIssuer_KeyStorage_RoundTrip(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()

	storage := NewBarrierView(core.barrier, oidcIssuerStorePrefix)
	ctx := context.Background()

	// No key yet -> (nil, nil, nil, nil).
	got, _, _, err := loadRS256(ctx, storage)
	if err != nil {
		t.Fatalf("loadKeySet (empty): %v", err)
	}
	if got != nil {
		t.Fatal("expected no signing key before one is persisted")
	}

	original, err := generateSigningKey(oidcAlgRS256)
	if err != nil {
		t.Fatalf("generateSigningKey (active): %v", err)
	}
	originalNext, err := generateSigningKey(oidcAlgRS256)
	if err != nil {
		t.Fatalf("generateSigningKey (next): %v", err)
	}

	// A keyset with no next key must be rejected.
	if err := persistRS256(ctx, storage, original, nil, nil); err == nil {
		t.Fatal("persistKeySet must reject a keyset with no next key")
	}

	if err := persistRS256(ctx, storage, original, originalNext, nil); err != nil {
		t.Fatalf("persistKeySet: %v", err)
	}

	loaded, loadedNext, _, err := loadRS256(ctx, storage)
	if err != nil {
		t.Fatalf("loadKeySet: %v", err)
	}
	if loaded == nil || loadedNext == nil {
		t.Fatal("expected both active and next keys after persist")
	}
	if loaded.kid != original.kid {
		t.Errorf("active kid mismatch: got %q want %q", loaded.kid, original.kid)
	}
	if !keyEqual(loaded.key, original.key) {
		t.Error("loaded active private key does not equal the persisted one")
	}
	if loadedNext.kid != originalNext.kid {
		t.Errorf("next kid mismatch: got %q want %q", loadedNext.kid, originalNext.kid)
	}
	if !keyEqual(loadedNext.key, originalNext.key) {
		t.Error("loaded next private key does not equal the persisted one")
	}

	// The reloaded key mints an assertion that verifies against the same key's JWKS.
	iss := NewOIDCIssuer("https://iss.example")
	iss.RestoreKeys(rs256Keyset(loaded, loadedNext, nil))
	jwks := serveJWKS(t, iss)
	tok, err := iss.MintIdentityAssertion(&logical.TokenEntry{PrincipalID: "p", NamespaceID: "n", MountAccessor: "m"}, "aud", time.Minute, nil, oidcAlgRS256)
	if err != nil {
		t.Fatalf("mint with reloaded key: %v", err)
	}
	keySet, err := jwt.NewJSONWebKeySet(ctx, jwks.URL, "")
	if err != nil {
		t.Fatalf("keyset: %v", err)
	}
	validator, err := jwt.NewValidator(keySet)
	if err != nil {
		t.Fatalf("validator: %v", err)
	}
	if _, err := validator.Validate(ctx, tok, jwt.Expected{
		Issuer: "https://iss.example", Audiences: []string{"aud"}, SigningAlgorithms: []jwt.Alg{jwt.RS256},
	}); err != nil {
		t.Errorf("assertion from reloaded key must verify: %v", err)
	}
}

// TestCore_setupOIDCIssuer covers the Core lifecycle wiring: disabled by
// default, active-node key generation, standby stays not-ready, and the key
// persists across setups.
func TestCore_setupOIDCIssuer(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()
	ctx := context.Background()
	storage := NewBarrierView(core.barrier, oidcIssuerStorePrefix)

	// Disabled by default: no config -> nil issuer.
	if err := core.setupOIDCIssuer(ctx, false); err != nil {
		t.Fatalf("setup (no config): %v", err)
	}
	if core.OIDCIssuer() != nil {
		t.Fatal("issuer must be disabled with no config")
	}

	// Config present but disabled -> still nil.
	if err := saveIssuerConfig(ctx, storage, &issuerConfig{Enabled: false, IssuerURL: "https://iss.example"}); err != nil {
		t.Fatalf("save disabled config: %v", err)
	}
	if err := core.setupOIDCIssuer(ctx, false); err != nil {
		t.Fatalf("setup (disabled): %v", err)
	}
	if core.OIDCIssuer() != nil {
		t.Fatal("issuer must stay disabled when Enabled=false")
	}

	// Enabled, no key yet, standby -> issuer present but not ready (cannot generate).
	if err := saveIssuerConfig(ctx, storage, &issuerConfig{Enabled: true, IssuerURL: "https://iss.example"}); err != nil {
		t.Fatalf("save enabled config: %v", err)
	}
	if err := core.setupOIDCIssuer(ctx, true /* standby */); err != nil {
		t.Fatalf("setup (standby): %v", err)
	}
	if iss := core.OIDCIssuer(); iss == nil || iss.Ready() {
		t.Fatal("standby with no key must produce a not-ready issuer")
	}
	if k, _, _, _ := loadRS256(ctx, storage); k != nil {
		t.Fatal("standby must not generate/persist a key")
	}

	// Enabled, active -> generates + persists a key, issuer ready and can mint.
	if err := core.setupOIDCIssuer(ctx, false /* active */); err != nil {
		t.Fatalf("setup (active): %v", err)
	}
	iss := core.OIDCIssuer()
	if iss == nil || !iss.Ready() {
		t.Fatal("active node must produce a ready issuer")
	}
	tok, err := iss.MintIdentityAssertion(&logical.TokenEntry{PrincipalID: "p", NamespaceID: "n", MountAccessor: "m"}, "aud", time.Minute, nil, oidcAlgRS256)
	if err != nil || tok == "" {
		t.Fatalf("ready issuer must mint: %v", err)
	}
	persisted, persistedNext, _, _ := loadRS256(ctx, storage)
	if persisted == nil || persistedNext == nil {
		t.Fatal("active node must persist both the active and next keys")
	}
	if persisted.kid == persistedNext.kid {
		t.Fatal("active and next keys must be distinct")
	}
	// The pre-published next key must be in the JWKS from the first setup.
	if kids := jwksKIDs(t, iss); !kids[persisted.kid] || !kids[persistedNext.kid] {
		t.Fatal("JWKS must contain both the active and next keys")
	}
	firstKid, firstNextKid := persisted.kid, persistedNext.kid

	// Re-setup (active) must reuse the persisted keys, not generate new ones.
	if err := core.setupOIDCIssuer(ctx, false); err != nil {
		t.Fatalf("setup (reuse): %v", err)
	}
	reloaded, reloadedNext, _, _ := loadRS256(ctx, storage)
	if reloaded == nil || reloaded.kid != firstKid {
		t.Fatal("re-setup must reuse the persisted active key")
	}
	if reloadedNext == nil || reloadedNext.kid != firstNextKid {
		t.Fatal("re-setup must reuse the persisted next key")
	}

	// Seal teardown clears the issuer.
	if err := core.stopOIDCIssuer(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if core.OIDCIssuer() != nil {
		t.Fatal("stopOIDCIssuer must clear the issuer")
	}
}

// jwksKIDs returns the set of key ids in an issuer's current JWKS.
func jwksKIDs(t *testing.T, iss *OIDCIssuer) map[string]bool {
	t.Helper()
	body, err := iss.JWKS()
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	var set struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil {
		t.Fatalf("unmarshal jwks: %v", err)
	}
	out := map[string]bool{}
	for _, k := range set.Keys {
		out[k.Kid] = true
	}
	return out
}

// spyPublisher records the JWKS bytes of each Publish call.
type spyPublisher struct{ jwks [][]byte }

func (s *spyPublisher) Type() string { return "spy" }
func (s *spyPublisher) Publish(_ context.Context, _, jwks []byte) error {
	s.jwks = append(s.jwks, append([]byte(nil), jwks...))
	return nil
}

func enableIssuer(t *testing.T, core *Core) *OIDCIssuer {
	t.Helper()
	ctx := context.Background()
	storage := NewBarrierView(core.barrier, oidcIssuerStorePrefix)
	require.NoError(t, saveIssuerConfig(ctx, storage, &issuerConfig{Enabled: true, IssuerURL: "https://iss.example"}))
	require.NoError(t, core.setupOIDCIssuer(ctx, false))
	iss := core.OIDCIssuer()
	require.NotNil(t, iss)
	require.True(t, iss.Ready())
	if _, next, _ := rs256Keys(iss); next == nil {
		t.Fatal("enabled issuer must have a pre-published next key")
	}
	return iss
}

// TestCore_setupOIDCIssuer_GeneratesAllAlgs verifies enabling the issuer generates
// a keyset for every supported algorithm, so a spec can select either with no cold
// start: the JWKS carries an RSA and an EC key (active+next each) and discovery
// advertises both algorithms.
func TestCore_setupOIDCIssuer_GeneratesAllAlgs(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()
	iss := enableIssuer(t, core)

	keysets := iss.Keys()
	require.NotNil(t, keysets[oidcAlgRS256], "RS256 keyset")
	require.NotNil(t, keysets[oidcAlgES256], "ES256 keyset")
	assert.NotNil(t, keysets[oidcAlgRS256].active)
	assert.NotNil(t, keysets[oidcAlgES256].active)

	// 2 algorithms x (active + next).
	assert.Len(t, jwksKIDs(t, iss), 4)

	disc, err := iss.DiscoveryDocument("https://iss.example/oidc/jwks")
	require.NoError(t, err)
	var d struct {
		Algs []string `json:"id_token_signing_alg_values_supported"`
	}
	require.NoError(t, json.Unmarshal(disc, &d))
	assert.ElementsMatch(t, []string{"RS256", "ES256"}, d.Algs)
}

// TestRotateOIDCKey covers one rotation with no external publisher: the active
// key changes, the old key is retired (still in the JWKS), and the keyset is
// persisted.
func TestRotateOIDCKey(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()
	ctx := context.Background()
	iss := enableIssuer(t, core)

	oldActive, oldNext, _ := rs256Keys(iss)

	require.NoError(t, core.rotateOIDCKey(ctx, iss, nil, 0, defaultRetiredKeyGrace))

	newActive, newNext, retired := rs256Keys(iss)
	assert.Equal(t, oldNext.kid, newActive.kid, "rotation must promote the next key to active")
	assert.NotEqual(t, newActive.kid, newNext.kid, "a fresh next key must be generated")
	assert.NotEqual(t, oldActive.kid, newNext.kid, "the new next key must be distinct from the old active")
	require.Len(t, retired, 1)
	assert.Equal(t, oldActive.kid, retired[0].kid, "the old active key must be retired")
	assert.False(t, retired[0].retiredAt.IsZero(), "retiredAt must be set")

	// JWKS carries active + next + retired.
	kids := jwksKIDs(t, iss)
	assert.True(t, kids[newActive.kid] && kids[newNext.kid] && kids[oldActive.kid], "JWKS must contain active, next, and retired keys")

	// Persisted keyset reflects the rotation.
	storage := NewBarrierView(core.barrier, oidcIssuerStorePrefix)
	pActive, pNext, pRetired, err := loadRS256(ctx, storage)
	require.NoError(t, err)
	assert.Equal(t, newActive.kid, pActive.kid)
	assert.Equal(t, newNext.kid, pNext.kid)
	require.Len(t, pRetired, 1)
	assert.Equal(t, oldActive.kid, pRetired[0].kid)
}

// TestOIDCIssuer_DerivedCacheControl verifies the Cache-Control is derived from
// the JWKS cache TTL and wired onto the issuer at setup.
func TestOIDCIssuer_DerivedCacheControl(t *testing.T) {
	assert.Equal(t, "public, max-age=120", oidcCacheControl(120*time.Second))
	assert.Equal(t, "public, max-age=0", oidcCacheControl(0))

	iss := NewOIDCIssuer("https://iss")
	iss.SetCacheControl(90 * time.Second)
	assert.Equal(t, "public, max-age=90", iss.CacheControl())

	// Setup derives it from jwks_cache_ttl.
	core := createTestCore(t)
	defer core.tokenStore.Close()
	ctx := context.Background()
	storage := NewBarrierView(core.barrier, oidcIssuerStorePrefix)
	require.NoError(t, saveIssuerConfig(ctx, storage, &issuerConfig{
		Enabled: true, IssuerURL: "https://iss.example", JWKSCacheTTL: "150s",
	}))
	require.NoError(t, core.setupOIDCIssuer(ctx, false))
	assert.Equal(t, "public, max-age=150", core.OIDCIssuer().CacheControl())
}

// TestOIDCIssuer_PruneRetired verifies retired keys are pruned by cutoff.
func TestOIDCIssuer_PruneRetired(t *testing.T) {
	iss, _, _ := newReadyIssuerWithNext(t, "https://iss.example")
	k3, err := generateSigningKey(oidcAlgRS256)
	require.NoError(t, err)
	// Rotate with a far-past cutoff so the freshly-retired old active is kept.
	require.NoError(t, iss.Rotate(oidcAlgRS256, k3, time.Now().Add(-time.Hour)))
	_, _, retired := rs256Keys(iss)
	require.Len(t, retired, 1)

	// Cutoff in the past keeps a freshly-retired key.
	assert.Equal(t, 0, iss.PruneRetired(time.Now().Add(-time.Hour)))
	_, _, retired = rs256Keys(iss)
	assert.Len(t, retired, 1)

	// Cutoff in the future prunes it.
	assert.Equal(t, 1, iss.PruneRetired(time.Now().Add(time.Hour)))
	_, _, retired = rs256Keys(iss)
	assert.Len(t, retired, 0)
}

// TestRotateOIDCKey_NextPrePublished proves the pre-published-next property: the
// next key is already in the JWKS before it is promoted to active, so a verifier
// can fetch it ahead of the first assertion it signs.
func TestRotateOIDCKey_NextPrePublished(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()
	ctx := context.Background()
	iss := enableIssuer(t, core)

	_, oldNext, _ := rs256Keys(iss)

	// The next key is in the JWKS before it ever signs.
	assert.True(t, jwksKIDs(t, iss)[oldNext.kid], "the next key must be published before activation")

	require.NoError(t, core.rotateOIDCKey(ctx, iss, nil, 0, defaultRetiredKeyGrace))

	newActive, _, _ := rs256Keys(iss)
	assert.Equal(t, oldNext.kid, newActive.kid, "the pre-published next key must become active")
}

// TestRotateOIDCKey_CancelDuringFloorWait verifies that a context cancelled during
// the propagation-floor wait aborts the rotation without mutating state: the active
// key is unchanged and the durable next key stays present (in memory and storage).
func TestRotateOIDCKey_CancelDuringFloorWait(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()
	iss := enableIssuer(t, core)

	before, beforeNext, _ := rs256Keys(iss)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled: the floor-wait select returns immediately

	// A large cache TTL forces the floor to be active: the next key was just created
	// at enable, so it is younger than the TTL and the rotation must wait — and here
	// the cancelled context aborts that wait.
	err := core.rotateOIDCKey(ctx, iss, &spyPublisher{}, time.Minute, defaultRetiredKeyGrace)
	require.Error(t, err)

	after, afterNext, retired := rs256Keys(iss)
	assert.Equal(t, before.kid, after.kid, "active key must be unchanged after an aborted rotation")
	assert.Equal(t, beforeNext.kid, afterNext.kid, "the durable next key must remain")
	assert.Len(t, retired, 0, "no key should be retired")

	// Persisted keyset still has the original active and next.
	storage := NewBarrierView(core.barrier, oidcIssuerStorePrefix)
	pActive, pNext, pRetired, _ := loadRS256(context.Background(), storage)
	assert.Equal(t, before.kid, pActive.kid)
	assert.Equal(t, beforeNext.kid, pNext.kid)
	assert.Len(t, pRetired, 0)
}

// TestRotateOIDCKey_PublishesOnceWithFullKeyset checks a steady-state rotation
// (floor already satisfied) publishes exactly once, with the promoted active, the
// fresh next, and the retired old active.
func TestRotateOIDCKey_PublishesOnceWithFullKeyset(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()
	iss := enableIssuer(t, core)
	spy := &spyPublisher{}
	oldActive, oldNext, _ := rs256Keys(iss)

	// cacheTTL=0 -> no floor wait; one publish after the flip.
	require.NoError(t, core.rotateOIDCKey(context.Background(), iss, spy, 0, defaultRetiredKeyGrace))
	newActive, newNext, _ := rs256Keys(iss)

	require.Len(t, spy.jwks, 1, "rotation must publish exactly once")
	var last struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(spy.jwks[len(spy.jwks)-1], &last))
	got := map[string]bool{}
	for _, k := range last.Keys {
		got[k.Kid] = true
	}
	assert.Equal(t, oldNext.kid, newActive.kid, "the next key must be promoted to active")
	assert.True(t, got[newActive.kid], "final JWKS must contain the new active key")
	assert.True(t, got[newNext.kid], "final JWKS must contain the new next key")
	assert.True(t, got[oldActive.kid], "final JWKS must retain the retired old key")
}

// TestOIDCKeyRotation_Lifecycle checks the goroutine lifecycle: a standby starts
// no loop; the active node starts one; and stop joins it.
func TestOIDCKeyRotation_Lifecycle(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()
	iss := enableIssuer(t, core)

	// Standby -> no loop.
	core.startOIDCKeyRotation(true, time.Hour, time.Hour, iss, nil, time.Minute, time.Hour)
	assert.Nil(t, core.oidcRotationCancel, "standby must not start a rotation loop")

	// period 0 -> no loop.
	core.startOIDCKeyRotation(false, 0, 0, iss, nil, time.Minute, time.Hour)
	assert.Nil(t, core.oidcRotationCancel)

	// Active + positive period -> loop started, with a far-future first tick so it
	// never fires during the test.
	core.startOIDCKeyRotation(false, time.Hour, time.Hour, iss, nil, time.Minute, time.Hour)
	require.NotNil(t, core.oidcRotationCancel, "active node must start the loop")
	require.NotNil(t, core.oidcRotationDone)
	done := core.oidcRotationDone

	// Stop joins the goroutine (done is closed) and clears the handles.
	core.stopOIDCKeyRotation()
	select {
	case <-done:
	default:
		t.Fatal("stopOIDCKeyRotation must join the loop (done not closed)")
	}
	assert.Nil(t, core.oidcRotationCancel)
	assert.Nil(t, core.oidcRotationDone)
}

// TestOIDCIssuer_Rotation checks that installing a new active key retires the old
// one and both remain in the JWKS so in-flight assertions still verify.
func TestOIDCIssuer_Rotation(t *testing.T) {
	iss, _, _ := newReadyIssuerWithNext(t, "https://iss.example")
	te := &logical.TokenEntry{PrincipalID: "p", NamespaceID: "n", MountAccessor: "m"}

	// Sign with key 1 (active), then rotate to promote the next key (key 2).
	tok1, err := iss.MintIdentityAssertion(te, "aud", 5*time.Minute, nil, oidcAlgRS256)
	if err != nil {
		t.Fatalf("mint 1: %v", err)
	}

	key3, err := generateSigningKey(oidcAlgRS256)
	if err != nil {
		t.Fatalf("generate key 3: %v", err)
	}
	// Far-past cutoff keeps the freshly-retired key 1 in the JWKS.
	require.NoError(t, iss.Rotate(oidcAlgRS256, key3, time.Now().Add(-time.Hour)))

	jwks := serveJWKS(t, iss)
	ctx := context.Background()
	keySet, err := jwt.NewJSONWebKeySet(ctx, jwks.URL, "")
	if err != nil {
		t.Fatalf("keyset: %v", err)
	}
	validator, err := jwt.NewValidator(keySet)
	if err != nil {
		t.Fatalf("validator: %v", err)
	}

	// The assertion signed by the retired key still verifies (grace window).
	if _, err := validator.Validate(ctx, tok1, jwt.Expected{
		Issuer: "https://iss.example", Audiences: []string{"aud"}, SigningAlgorithms: []jwt.Alg{jwt.RS256},
	}); err != nil {
		t.Errorf("assertion from retired key must still verify during the grace window: %v", err)
	}

	// A new assertion signed by the active key verifies too.
	tok2, err := iss.MintIdentityAssertion(te, "aud", 5*time.Minute, nil, oidcAlgRS256)
	if err != nil {
		t.Fatalf("mint 2: %v", err)
	}
	if _, err := validator.Validate(ctx, tok2, jwt.Expected{
		Issuer: "https://iss.example", Audiences: []string{"aud"}, SigningAlgorithms: []jwt.Alg{jwt.RS256},
	}); err != nil {
		t.Errorf("assertion from active key must verify: %v", err)
	}
}

// TestOIDCIssuer_Rotate_NoNext verifies Rotate/PendingRotation refuse and leave
// state untouched when there is no next key to promote.
func TestOIDCIssuer_Rotate_NoNext(t *testing.T) {
	iss := newReadyIssuer(t, "https://iss.example") // active only, no next
	activeBefore, nextBefore, _ := rs256Keys(iss)
	require.NotNil(t, activeBefore)
	require.Nil(t, nextBefore)

	newNext, err := generateSigningKey(oidcAlgRS256)
	require.NoError(t, err)

	_, _, perr := iss.PendingRotation(oidcAlgRS256, time.Now())
	assert.Error(t, perr, "PendingRotation must error without a next key")

	assert.Error(t, iss.Rotate(oidcAlgRS256, newNext, time.Now()), "Rotate must error without a next key")

	activeAfter, nextAfter, retired := rs256Keys(iss)
	assert.Equal(t, activeBefore.kid, activeAfter.kid, "active must be unchanged")
	assert.Nil(t, nextAfter, "next must remain nil")
	assert.Len(t, retired, 0)
}

// TestOIDCKeyRotation_FirstTickAnchor is the restart-churn regression guard: the
// first rotation must be scheduled off the NEXT key's age, not the active key's.
// A restarted node whose active key is ~one period old but whose next key is recent
// must NOT rotate immediately.
func TestOIDCKeyRotation_FirstTickAnchor(t *testing.T) {
	const period = time.Hour
	active, err := generateSigningKey(oidcAlgRS256)
	require.NoError(t, err)
	next, err := generateSigningKey(oidcAlgRS256)
	require.NoError(t, err)

	// Simulate a restart shortly after a rotation: the active key was minted a full
	// period ago (as the previous cycle's next); the next key was minted just now.
	active.createdAt = time.Now().Add(-period)
	next.createdAt = time.Now()

	firstTick := oidcRotationFirstTick(rs256Keyset(active, next, nil), period)

	// Anchored on next.createdAt+period, the first tick is ~a full period out, NOT ~0.
	assert.Greater(t, firstTick, period-time.Minute, "first tick must anchor on the next key, not fire immediately")

	// Sanity: anchoring on the active key would (wrongly) be ~0 or negative.
	assert.LessOrEqual(t, time.Until(active.createdAt.Add(period)), time.Minute)
}

// TestRotateOIDCKey_PropagationFloor verifies the floor waits only when the next
// key is younger than the cache TTL, and skips the wait when it is old enough. The
// cache TTL is set well above the cost of a rotation (RSA keygen + persist) so the
// wait/no-wait separation stays robust under parallel test load.
func TestRotateOIDCKey_PropagationFloor(t *testing.T) {
	const cacheTTL = 600 * time.Millisecond

	t.Run("young next waits", func(t *testing.T) {
		core := createTestCore(t)
		defer core.tokenStore.Close()
		iss := enableIssuer(t, core) // next created ~now
		start := time.Now()
		require.NoError(t, core.rotateOIDCKey(context.Background(), iss, &spyPublisher{}, cacheTTL, defaultRetiredKeyGrace))
		assert.GreaterOrEqual(t, time.Since(start), 450*time.Millisecond, "a young next key must wait out most of the floor")
	})

	t.Run("old next does not wait", func(t *testing.T) {
		core := createTestCore(t)
		defer core.tokenStore.Close()
		iss := enableIssuer(t, core)
		// Age the next key past the cache TTL so the floor is already satisfied.
		active, next, retired := rs256Keys(iss)
		next.createdAt = time.Now().Add(-time.Hour)
		iss.RestoreKeys(rs256Keyset(active, next, retired))
		start := time.Now()
		require.NoError(t, core.rotateOIDCKey(context.Background(), iss, &spyPublisher{}, cacheTTL, defaultRetiredKeyGrace))
		assert.Less(t, time.Since(start), 300*time.Millisecond, "an old-enough next key must not wait")
	})
}

// TestRotateOIDCKey_NoFloorWithoutPublisher verifies that with no external
// publisher the floor is skipped entirely (the built-in endpoint serves live).
func TestRotateOIDCKey_NoFloorWithoutPublisher(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()
	iss := enableIssuer(t, core) // next created ~now
	start := time.Now()
	// Large cache TTL, but publisher == nil -> no wait. The bound sits well below
	// the TTL yet above a rotation's RSA-keygen cost so the check is not flaky.
	require.NoError(t, core.rotateOIDCKey(context.Background(), iss, nil, time.Minute, defaultRetiredKeyGrace))
	assert.Less(t, time.Since(start), 300*time.Millisecond, "no publisher means no propagation floor")
}
