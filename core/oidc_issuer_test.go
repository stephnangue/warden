package core

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hashicorp/cap/jwt"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newReadyIssuer(t *testing.T, issuerURL string) *OIDCIssuer {
	t.Helper()
	iss := NewOIDCIssuer(issuerURL)
	key, err := generateSigningKey()
	if err != nil {
		t.Fatalf("generateSigningKey: %v", err)
	}
	iss.SetActiveKey(key)
	return iss
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

	token, err := iss.MintIdentityAssertion(te, audience, 5*time.Minute)
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

// TestOIDCIssuer_FailClosed covers the cases where minting must refuse.
func TestOIDCIssuer_FailClosed(t *testing.T) {
	te := &logical.TokenEntry{PrincipalID: "p", NamespaceID: "n", MountAccessor: "m"}

	// Not ready: no active key.
	notReady := NewOIDCIssuer("https://iss.example")
	if notReady.Ready() {
		t.Fatal("issuer with no key must not be ready")
	}
	if _, err := notReady.MintIdentityAssertion(te, "aud", time.Minute); err == nil {
		t.Error("mint must fail closed when no active key is installed")
	}

	ready := newReadyIssuer(t, "https://iss.example")
	if _, err := ready.MintIdentityAssertion(te, "", time.Minute); err == nil {
		t.Error("mint must fail closed on empty audience")
	}
	if _, err := ready.MintIdentityAssertion(nil, "aud", time.Minute); err == nil {
		t.Error("mint must fail closed on nil token entry")
	}
	if _, err := ready.MintIdentityAssertion(&logical.TokenEntry{}, "aud", time.Minute); err == nil {
		t.Error("mint must fail closed when the principal is empty")
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

	// No key yet -> (nil, nil, nil).
	got, _, err := loadKeySet(ctx, storage)
	if err != nil {
		t.Fatalf("loadKeySet (empty): %v", err)
	}
	if got != nil {
		t.Fatal("expected no signing key before one is persisted")
	}

	original, err := generateSigningKey()
	if err != nil {
		t.Fatalf("generateSigningKey: %v", err)
	}
	if err := persistKeySet(ctx, storage, original, nil); err != nil {
		t.Fatalf("persistKeySet: %v", err)
	}

	loaded, _, err := loadKeySet(ctx, storage)
	if err != nil {
		t.Fatalf("loadKeySet: %v", err)
	}
	if loaded == nil {
		t.Fatal("expected a signing key after persist")
	}
	if loaded.kid != original.kid {
		t.Errorf("kid mismatch: got %q want %q", loaded.kid, original.kid)
	}
	if !loaded.key.Equal(original.key) {
		t.Error("loaded private key does not equal the persisted one")
	}

	// The reloaded key mints an assertion that verifies against the same key's JWKS.
	iss := NewOIDCIssuer("https://iss.example")
	iss.SetActiveKey(loaded)
	jwks := serveJWKS(t, iss)
	tok, err := iss.MintIdentityAssertion(&logical.TokenEntry{PrincipalID: "p", NamespaceID: "n", MountAccessor: "m"}, "aud", time.Minute)
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
	if k, _, _ := loadKeySet(ctx, storage); k != nil {
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
	tok, err := iss.MintIdentityAssertion(&logical.TokenEntry{PrincipalID: "p", NamespaceID: "n", MountAccessor: "m"}, "aud", time.Minute)
	if err != nil || tok == "" {
		t.Fatalf("ready issuer must mint: %v", err)
	}
	persisted, _, _ := loadKeySet(ctx, storage)
	if persisted == nil {
		t.Fatal("active node must persist the generated key")
	}
	firstKid := persisted.kid

	// Re-setup (active) must reuse the persisted key, not generate a new one.
	if err := core.setupOIDCIssuer(ctx, false); err != nil {
		t.Fatalf("setup (reuse): %v", err)
	}
	reloaded, _, _ := loadKeySet(ctx, storage)
	if reloaded == nil || reloaded.kid != firstKid {
		t.Fatal("re-setup must reuse the persisted signing key")
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
	return iss
}

// TestRotateOIDCKey covers one rotation with no external publisher: the active
// key changes, the old key is retired (still in the JWKS), and the keyset is
// persisted.
func TestRotateOIDCKey(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()
	ctx := context.Background()
	iss := enableIssuer(t, core)

	oldActive, _ := iss.Keys()
	oldKid := oldActive.kid

	require.NoError(t, core.rotateOIDCKey(ctx, iss, nil, 0, defaultKeyOverlap))

	newActive, retired := iss.Keys()
	assert.NotEqual(t, oldKid, newActive.kid, "active key must change on rotation")
	require.Len(t, retired, 1)
	assert.Equal(t, oldKid, retired[0].kid, "the old key must be retired")
	assert.False(t, retired[0].retiredAt.IsZero(), "retiredAt must be set")

	// JWKS carries both keys during overlap.
	kids := jwksKIDs(t, iss)
	assert.True(t, kids[newActive.kid] && kids[oldKid], "JWKS must contain both keys")

	// Persisted keyset reflects the rotation.
	storage := NewBarrierView(core.barrier, oidcIssuerStorePrefix)
	pActive, pRetired, err := loadKeySet(ctx, storage)
	require.NoError(t, err)
	assert.Equal(t, newActive.kid, pActive.kid)
	require.Len(t, pRetired, 1)
	assert.Equal(t, oldKid, pRetired[0].kid)
}

// TestOIDCIssuer_DerivedCacheControl verifies the Cache-Control is derived from
// the activation delay and wired onto the issuer at setup.
func TestOIDCIssuer_DerivedCacheControl(t *testing.T) {
	assert.Equal(t, "public, max-age=120", oidcCacheControl(120*time.Second))
	assert.Equal(t, "public, max-age=0", oidcCacheControl(0))

	iss := NewOIDCIssuer("https://iss")
	iss.SetCacheControl(90 * time.Second)
	assert.Equal(t, "public, max-age=90", iss.CacheControl())

	// Setup derives it from key_activation_delay.
	core := createTestCore(t)
	defer core.tokenStore.Close()
	ctx := context.Background()
	storage := NewBarrierView(core.barrier, oidcIssuerStorePrefix)
	require.NoError(t, saveIssuerConfig(ctx, storage, &issuerConfig{
		Enabled: true, IssuerURL: "https://iss.example", KeyActivationDelay: "150s",
	}))
	require.NoError(t, core.setupOIDCIssuer(ctx, false))
	assert.Equal(t, "public, max-age=150", core.OIDCIssuer().CacheControl())
}

// TestOIDCIssuer_PruneRetired verifies retired keys are pruned by cutoff.
func TestOIDCIssuer_PruneRetired(t *testing.T) {
	iss := newReadyIssuer(t, "https://iss.example")
	k2, err := generateSigningKey()
	require.NoError(t, err)
	iss.SetActiveKey(k2) // retires k1 with retiredAt=now
	_, retired := iss.Keys()
	require.Len(t, retired, 1)

	// Cutoff in the past keeps a freshly-retired key.
	assert.Equal(t, 0, iss.PruneRetired(time.Now().Add(-time.Hour)))
	_, retired = iss.Keys()
	assert.Len(t, retired, 1)

	// Cutoff in the future prunes it.
	assert.Equal(t, 1, iss.PruneRetired(time.Now().Add(time.Hour)))
	_, retired = iss.Keys()
	assert.Len(t, retired, 0)
}

// TestRotateOIDCKey_StagesBeforeActivate proves the two-stage ordering: the new
// key is published (staged) before it becomes active, so a verifier can fetch it
// first.
func TestRotateOIDCKey_StagesBeforeActivate(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()
	ctx := context.Background()
	iss := enableIssuer(t, core)

	spy := &spyPublisher{}

	oldActive, _ := iss.Keys()
	oldKid := oldActive.kid

	// 5ms activation delay keeps the test fast while still exercising the wait.
	require.NoError(t, core.rotateOIDCKey(ctx, iss, spy, 5*time.Millisecond, defaultKeyOverlap))
	newActive, _ := iss.Keys()

	require.GreaterOrEqual(t, len(spy.jwks), 1, "the staged key must be published")
	// The very first publish (staged, pre-activation) already contains the
	// new key alongside the still-active old key.
	var first struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(spy.jwks[0], &first))
	got := map[string]bool{}
	for _, k := range first.Keys {
		got[k.Kid] = true
	}
	assert.True(t, got[newActive.kid], "the new key must be in the JWKS before it is activated")
	assert.True(t, got[oldKid], "the old (still-active) key must also be present")
}

// TestRotateOIDCKey_CancelAbandonsStage verifies that a context cancelled during
// the activation delay abandons the staged key: the active key is unchanged, the
// keyset is not persisted, and no orphan key is left staged.
func TestRotateOIDCKey_CancelAbandonsStage(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()
	iss := enableIssuer(t, core)

	before, _ := iss.Keys()
	beforeKid := before.kid

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled: the activation-delay select returns immediately

	err := core.rotateOIDCKey(ctx, iss, &spyPublisher{}, time.Minute, defaultKeyOverlap)
	require.Error(t, err)

	after, retired := iss.Keys()
	assert.Equal(t, beforeKid, after.kid, "active key must be unchanged after an aborted rotation")
	assert.Len(t, retired, 0, "no key should be retired")
	assert.Len(t, jwksKIDs(t, iss), 1, "no staged key should remain in the JWKS")

	// Persisted keyset still has only the original active.
	storage := NewBarrierView(core.barrier, oidcIssuerStorePrefix)
	pActive, pRetired, _ := loadKeySet(context.Background(), storage)
	assert.Equal(t, beforeKid, pActive.kid)
	assert.Len(t, pRetired, 0)
}

// TestRotateOIDCKey_RepublishesFinalKeyset checks the post-activation republish:
// the last published JWKS contains the new active and the retired old key.
func TestRotateOIDCKey_RepublishesFinalKeyset(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()
	iss := enableIssuer(t, core)
	spy := &spyPublisher{}
	oldActive, _ := iss.Keys()

	require.NoError(t, core.rotateOIDCKey(context.Background(), iss, spy, 0, defaultKeyOverlap))
	newActive, _ := iss.Keys()

	require.GreaterOrEqual(t, len(spy.jwks), 2, "staged publish + final republish")
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
	assert.True(t, got[newActive.kid], "final JWKS must contain the new active key")
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
	iss := newReadyIssuer(t, "https://iss.example")
	te := &logical.TokenEntry{PrincipalID: "p", NamespaceID: "n", MountAccessor: "m"}

	// Sign with key 1, then rotate.
	tok1, err := iss.MintIdentityAssertion(te, "aud", 5*time.Minute)
	if err != nil {
		t.Fatalf("mint 1: %v", err)
	}

	key2, err := generateSigningKey()
	if err != nil {
		t.Fatalf("generate key 2: %v", err)
	}
	iss.SetActiveKey(key2)

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

	// The assertion signed by the retired key still verifies (overlap window).
	if _, err := validator.Validate(ctx, tok1, jwt.Expected{
		Issuer: "https://iss.example", Audiences: []string{"aud"}, SigningAlgorithms: []jwt.Alg{jwt.RS256},
	}); err != nil {
		t.Errorf("assertion from retired key must still verify during overlap: %v", err)
	}

	// A new assertion signed by the active key verifies too.
	tok2, err := iss.MintIdentityAssertion(te, "aud", 5*time.Minute)
	if err != nil {
		t.Fatalf("mint 2: %v", err)
	}
	if _, err := validator.Validate(ctx, tok2, jwt.Expected{
		Issuer: "https://iss.example", Audiences: []string{"aud"}, SigningAlgorithms: []jwt.Alg{jwt.RS256},
	}); err != nil {
		t.Errorf("assertion from active key must verify: %v", err)
	}
}
