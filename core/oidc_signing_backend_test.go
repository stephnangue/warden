package core

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/cap/jwt"
	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/core/oidcsign"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeSignBackend is an in-memory oidcsign.Backend for tests: it holds a real
// RSA/ECDSA key per alg version and signs by delegating to the underlying
// crypto.Signer, so its output matches the crypto.Signer contract exactly (RSA
// PKCS#1 v1.5, ECDSA ASN.1 DER) and minted assertions verify against the JWKS.
type fakeSignBackend struct {
	t        *testing.T
	mu       sync.Mutex
	closed   bool
	opErr    error                      // when set, EnsureKey/NewVersion fail (simulate KMS down)
	versions map[string][]crypto.Signer // alg -> keys, index 0 == version 1
}

func newFakeSignBackend(t *testing.T) *fakeSignBackend {
	return &fakeSignBackend{t: t, versions: map[string][]crypto.Signer{}}
}

func genForAlg(t *testing.T, alg string) crypto.Signer {
	t.Helper()
	switch alg {
	case oidcAlgRS256:
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		return k
	case oidcAlgES256:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		return k
	}
	t.Fatalf("fake backend: unhandled alg %q", alg)
	return nil
}

func (f *fakeSignBackend) Type() string { return "transit" }

func (f *fakeSignBackend) infoLocked(alg string) oidcsign.KeyInfo {
	vers := f.versions[alg]
	ver := len(vers)
	return oidcsign.KeyInfo{
		Ref:       oidcsign.KeyRef{KeyName: "fake-" + alg, Version: ver, Alg: alg},
		Public:    vers[ver-1].Public(),
		CreatedAt: time.Now().Add(time.Duration(ver) * time.Second),
	}
}

func (f *fakeSignBackend) EnsureKey(_ context.Context, alg string) (oidcsign.KeyInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.opErr != nil {
		return oidcsign.KeyInfo{}, f.opErr
	}
	if len(f.versions[alg]) == 0 {
		f.versions[alg] = []crypto.Signer{genForAlg(f.t, alg)}
	}
	return f.infoLocked(alg), nil
}

func (f *fakeSignBackend) NewVersion(_ context.Context, alg string) (oidcsign.KeyInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.opErr != nil {
		return oidcsign.KeyInfo{}, f.opErr
	}
	f.versions[alg] = append(f.versions[alg], genForAlg(f.t, alg))
	return f.infoLocked(alg), nil
}

func (f *fakeSignBackend) PublicKey(_ context.Context, ref oidcsign.KeyRef) (crypto.PublicKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.versions[ref.Alg][ref.Version-1].Public(), nil
}

func (f *fakeSignBackend) Sign(_ context.Context, ref oidcsign.KeyRef, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	f.mu.Lock()
	signer := f.versions[ref.Alg][ref.Version-1]
	f.mu.Unlock()
	return signer.Sign(rand.Reader, digest, opts)
}

func (f *fakeSignBackend) Close() { f.closed = true }

func TestRemoteKeySource_BootstrapAndNext(t *testing.T) {
	fake := newFakeSignBackend(t)
	src := remoteKeySource{backend: fake, timeout: time.Second}
	ctx := context.Background()

	active, next, err := src.bootstrap(ctx, oidcAlgRS256)
	require.NoError(t, err)
	// active is v1, next is v2, distinct kids.
	assert.NotEqual(t, active.kid, next.kid)
	// kid must equal the thumbprint of the (remote) public key — identical to a
	// local key's kid, so it is stable regardless of where the key lives.
	wantKid := rsaThumbprint(active.key.Public().(*rsa.PublicKey))
	assert.Equal(t, wantKid, active.kid)
	// createdAt comes from the backend (KMS creation time), not time.Now here.
	assert.False(t, active.createdAt.IsZero())
	// The signingKey is remote (KMS-backed).
	assert.True(t, isRemoteSigningKey(active))

	nk, err := src.nextKey(ctx, oidcAlgRS256)
	require.NoError(t, err)
	assert.NotEqual(t, next.kid, nk.kid, "rotation must yield a new version/kid")
}

func TestStorageV4_RemoteRoundTrip(t *testing.T) {
	fake := newFakeSignBackend(t)
	info, err := fake.EnsureKey(context.Background(), oidcAlgRS256)
	require.NoError(t, err)
	kid, err := signingKeyID(info.Public)
	require.NoError(t, err)
	sk := &signingKey{key: oidcsign.NewSigner(fake, info.Ref, info.Public, time.Second), alg: oidcAlgRS256, kid: kid, createdAt: info.CreatedAt}

	stored, err := toStored(sk)
	require.NoError(t, err)
	require.NotNil(t, stored.Remote, "a remote key must serialize as a handle")
	assert.Empty(t, stored.KeyPKCS8, "no private material may be stored for a remote key")
	assert.Equal(t, "transit", stored.Remote.Backend)
	assert.Equal(t, info.Ref.KeyName, stored.Remote.KeyName)

	// With a matching backend -> signing-capable.
	back, err := fromStored(stored, fake, time.Second)
	require.NoError(t, err)
	assert.Equal(t, kid, back.kid)
	rs := back.key.(*oidcsign.Signer)
	assert.True(t, rs.CanSign())

	// With no backend -> verification-only (fails closed on Sign) but same public key/kid.
	vonly, err := fromStored(stored, nil, 0)
	require.NoError(t, err)
	assert.False(t, vonly.key.(*oidcsign.Signer).CanSign())
	assert.Equal(t, kid, vonly.kid)

	// A tampered kid is rejected (the kid is a pure function of the public key).
	bad := stored
	bad.Kid = "tampered"
	_, err = fromStored(bad, fake, time.Second)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "kid mismatch")
}

func TestOIDCKeySetSourceMismatch_and_Cutover(t *testing.T) {
	fake := newFakeSignBackend(t)
	src := remoteKeySource{backend: fake, timeout: time.Second}
	ctx := context.Background()

	// A remote keyset vs a local config = mismatch; vs a remote config = match.
	rActive, rNext, err := src.bootstrap(ctx, oidcAlgRS256)
	require.NoError(t, err)
	remoteKeysets := map[string]*algKeyset{oidcAlgRS256: {active: rActive, next: rNext}}
	assert.True(t, oidcKeySetSourceMismatch(remoteKeysets, false), "remote keys vs local config is a mismatch")
	assert.False(t, oidcKeySetSourceMismatch(remoteKeysets, true), "remote keys vs remote config matches")

	// A local keyset vs remote config = mismatch.
	localKeysets := map[string]*algKeyset{oidcAlgRS256: {active: mustGen(t, oidcAlgRS256), next: mustGen(t, oidcAlgRS256)}}
	assert.True(t, oidcKeySetSourceMismatch(localKeysets, true))

	// Cutover retires active+next into retired, leaving the keyset incomplete.
	retireOIDCKeysetsForCutover(remoteKeysets)
	ks := remoteKeysets[oidcAlgRS256]
	assert.Nil(t, ks.active)
	assert.Nil(t, ks.next)
	assert.Len(t, ks.retired, 2)
	for _, r := range ks.retired {
		assert.False(t, r.retiredAt.IsZero(), "retired keys must be stamped")
	}
}

func TestOIDCActiveKeyNeedsCutover(t *testing.T) {
	fake := newFakeSignBackend(t)
	info, err := fake.EnsureKey(context.Background(), oidcAlgRS256)
	require.NoError(t, err)

	local := mustGen(t, oidcAlgRS256)
	remoteSigning := &signingKey{key: oidcsign.NewSigner(fake, info.Ref, info.Public, time.Second)}
	// A remote key whose backend is absent/different — reconstructed verify-only.
	remoteVerifyOnly := &signingKey{key: oidcsign.NewVerifyingSigner("transit", info.Ref, info.Public)}

	// Local config: only remote keys need to go.
	assert.False(t, oidcActiveKeyNeedsCutover(local, false))
	assert.True(t, oidcActiveKeyNeedsCutover(remoteSigning, false))
	assert.True(t, oidcActiveKeyNeedsCutover(remoteVerifyOnly, false))

	// Remote config: a local key goes, a signing remote key stays, and a
	// verify-only remote key (wrong/removed backend) must ALSO go — otherwise a
	// future second backend type would silently install an unusable active key.
	assert.True(t, oidcActiveKeyNeedsCutover(local, true))
	assert.False(t, oidcActiveKeyNeedsCutover(remoteSigning, true))
	assert.True(t, oidcActiveKeyNeedsCutover(remoteVerifyOnly, true))
}

// setupRemoteIssuer enables the issuer and installs the fake backend on core, then
// runs an active setup. Returns the storage view for assertions.
func setupRemoteIssuer(t *testing.T, core *Core, fake oidcsign.Backend) {
	t.Helper()
	ctx := context.Background()
	storage := NewBarrierView(core.barrier, oidcIssuerStorePrefix)
	require.NoError(t, saveIssuerConfig(ctx, storage, &issuerConfig{Enabled: true, IssuerURL: "https://iss.example"}))
	// Pre-install the backend so ensureOIDCSignBackend adopts it instead of building
	// a real transit client from HCL.
	core.oidcSignBackend = fake
	core.oidcSignTimeout = time.Second
	require.NoError(t, core.setupOIDCIssuer(ctx, false /* active */, false))
}

func TestCore_setupOIDCIssuer_Remote(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()
	fake := newFakeSignBackend(t)
	setupRemoteIssuer(t, core, fake)

	iss := core.OIDCIssuer()
	require.NotNil(t, iss)
	require.True(t, iss.Ready(), "remote-backed issuer must be ready")

	// The persisted keyset holds remote handles, not private material.
	storage := NewBarrierView(core.barrier, oidcIssuerStorePrefix)
	entry, err := storage.Get(context.Background(), oidcKeySetPath)
	require.NoError(t, err)
	require.NotNil(t, entry)
	assert.Contains(t, string(entry.Value), "\"remote\":", "keyset must store remote handles")
	assert.NotContains(t, string(entry.Value), "key_pkcs8", "no private key material may be persisted")

	// A minted assertion verifies against the served JWKS (public keys from the KMS).
	jwks := serveJWKS(t, iss)
	tok, err := iss.MintIdentityAssertion(context.Background(),
		&logical.TokenEntry{PrincipalID: "p", NamespaceID: "n", MountAccessor: "m"},
		AssertionClaims{Audience: "aud", TTL: time.Minute, Alg: oidcAlgRS256})
	require.NoError(t, err)

	ctx := context.Background()
	keySet, err := jwt.NewJSONWebKeySet(ctx, jwks.URL, "")
	require.NoError(t, err)
	validator, err := jwt.NewValidator(keySet)
	require.NoError(t, err)
	_, err = validator.Validate(ctx, tok, jwt.Expected{
		Issuer: "https://iss.example", Audiences: []string{"aud"}, SigningAlgorithms: []jwt.Alg{jwt.RS256},
	})
	require.NoError(t, err, "remotely-signed assertion must verify against the JWKS")

	// ES256 through the remote path too: transit returns ASN.1, signJWT converts to
	// R‖S, and the assertion must verify — the combination no other test exercises.
	tokES, err := iss.MintIdentityAssertion(ctx,
		&logical.TokenEntry{PrincipalID: "p", NamespaceID: "n", MountAccessor: "m"},
		AssertionClaims{Audience: "aud", TTL: time.Minute, Alg: oidcAlgES256})
	require.NoError(t, err)
	_, err = validator.Validate(ctx, tokES, jwt.Expected{
		Issuer: "https://iss.example", Audiences: []string{"aud"}, SigningAlgorithms: []jwt.Alg{jwt.ES256},
	})
	require.NoError(t, err, "remotely-signed ES256 assertion must verify against the JWKS")
}

// TestCore_setupOIDCIssuer_RemoteDegrade covers the degrade-not-brick behavior: an
// unreachable KMS at first enable must not fail unseal, but must fail the operator
// config-write path, and the issuer recovers once the KMS is reachable again.
func TestCore_setupOIDCIssuer_RemoteDegrade(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()
	ctx := context.Background()
	storage := NewBarrierView(core.barrier, oidcIssuerStorePrefix)
	require.NoError(t, saveIssuerConfig(ctx, storage, &issuerConfig{Enabled: true, IssuerURL: "https://iss.example"}))

	fake := newFakeSignBackend(t)
	fake.opErr = errors.New("transit unreachable")
	core.oidcSignBackend = fake
	core.oidcSignTimeout = time.Second

	// Unseal path: must NOT brick — install a not-ready issuer and return nil.
	require.NoError(t, core.setupOIDCIssuer(ctx, false /* active */, false /* unseal */))
	iss := core.OIDCIssuer()
	require.NotNil(t, iss)
	require.False(t, iss.Ready(), "issuer must be not-ready when the KMS is unreachable at enable")
	_, err := iss.MintIdentityAssertion(ctx,
		&logical.TokenEntry{PrincipalID: "p", NamespaceID: "n", MountAccessor: "m"},
		AssertionClaims{Audience: "aud", TTL: time.Minute, Alg: oidcAlgRS256})
	require.Error(t, err, "mint must fail closed while not ready")

	// Config-write path: must surface the error to the operator.
	require.Error(t, core.setupOIDCIssuer(ctx, false, true /* configWrite */),
		"config-write must surface an unreachable-KMS error")

	// Recovery: the KMS comes back; the next setup provisions and becomes ready.
	fake.opErr = nil
	require.NoError(t, core.setupOIDCIssuer(ctx, false, false))
	require.True(t, core.OIDCIssuer().Ready(), "issuer must recover once the KMS is reachable")
}

// TestCore_rotateOIDCKey_Remote drives a full rotation cycle with a KMS-backed key
// source: the pre-published next is promoted, a fresh next is provisioned from the
// KMS, the old active is retired, and the result is persisted — all remote.
func TestCore_rotateOIDCKey_Remote(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()
	ctx := context.Background()
	fake := newFakeSignBackend(t)
	setupRemoteIssuer(t, core, fake)
	iss := core.OIDCIssuer()

	before := iss.Keys()[oidcAlgRS256]
	oldActive, oldNext := before.active.kid, before.next.kid

	src := remoteKeySource{backend: fake, timeout: time.Second}
	require.NoError(t, core.rotateOIDCKey(ctx, src, iss, nil, 0, defaultRetiredKeyGrace))

	after := iss.Keys()[oidcAlgRS256]
	assert.Equal(t, oldNext, after.active.kid, "the pre-published next must be promoted to active")
	assert.NotEqual(t, oldNext, after.next.kid, "a fresh next must be provisioned from the KMS")
	assert.True(t, isRemoteSigningKey(after.active) && isRemoteSigningKey(after.next), "rotated keys stay remote")
	foundRetired := false
	for _, r := range after.retired {
		if r.kid == oldActive {
			foundRetired = true
		}
	}
	assert.True(t, foundRetired, "the old active key must be retired")

	// The rotation must be persisted before the in-memory flip.
	reloaded, err := loadKeySet(ctx, NewBarrierView(core.barrier, oidcIssuerStorePrefix), fake, time.Second, core.logger)
	require.NoError(t, err)
	assert.Equal(t, oldNext, reloaded[oidcAlgRS256].active.kid, "the promoted active must be in storage")
}

// TestCore_OIDCSignBackend_ClosedOnDisableAndStop asserts the KMS backend is closed
// (its token released) when the issuer is disabled and on teardown, so a standby
// holds no idle token.
func TestCore_OIDCSignBackend_ClosedOnDisableAndStop(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()
	ctx := context.Background()
	storage := NewBarrierView(core.barrier, oidcIssuerStorePrefix)

	fake := newFakeSignBackend(t)
	setupRemoteIssuer(t, core, fake)
	require.NotNil(t, core.oidcSignBackend)

	// Disabling the issuer closes and drops the backend.
	require.NoError(t, saveIssuerConfig(ctx, storage, &issuerConfig{Enabled: false, IssuerURL: "https://iss.example"}))
	require.NoError(t, core.setupOIDCIssuer(ctx, false, false))
	assert.True(t, fake.closed, "backend must be closed when the issuer is disabled")
	assert.Nil(t, core.oidcSignBackend, "backend reference must be dropped on disable")

	// Re-enable, then stopOIDCIssuer (seal/step-down) closes it too.
	fake2 := newFakeSignBackend(t)
	setupRemoteIssuer(t, core, fake2)
	require.NotNil(t, core.oidcSignBackend)
	require.NoError(t, core.stopOIDCIssuer())
	assert.True(t, fake2.closed, "backend must be closed on stopOIDCIssuer")
	assert.Nil(t, core.oidcSignBackend)
}

// TestLoadKeySet_CorruptRetiredVsActive verifies the availability trade-off: a
// corrupt retired key is dropped with a warning (not fatal), but a corrupt
// active/next key fails the load loudly.
func TestLoadKeySet_CorruptRetiredVsActive(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()
	ctx := context.Background()
	storage := NewBarrierView(core.barrier, oidcIssuerStorePrefix)
	fake := newFakeSignBackend(t)
	src := remoteKeySource{backend: fake, timeout: time.Second}

	active, next, err := src.bootstrap(ctx, oidcAlgRS256)
	require.NoError(t, err)
	ret, err := src.nextKey(ctx, oidcAlgRS256)
	require.NoError(t, err)
	ret.retiredAt = time.Now()

	persist := func() {
		require.NoError(t, persistKeySet(ctx, storage,
			map[string]*algKeyset{oidcAlgRS256: {active: active, next: next, retired: []*signingKey{ret}}}))
	}
	// tamperKid corrupts the kid of one stored key so its recomputed thumbprint no
	// longer matches, then writes the keyset back.
	tamperKid := func(slot string, idx int) {
		entry, err := storage.Get(ctx, oidcKeySetPath)
		require.NoError(t, err)
		var set map[string]interface{}
		require.NoError(t, json.Unmarshal(entry.Value, &set))
		rs := set["keysets"].(map[string]interface{})[oidcAlgRS256].(map[string]interface{})
		switch v := rs[slot].(type) {
		case map[string]interface{}:
			v["kid"] = "tampered"
		case []interface{}:
			v[idx].(map[string]interface{})["kid"] = "tampered"
		}
		val, err := json.Marshal(set)
		require.NoError(t, err)
		require.NoError(t, storage.Put(ctx, &sdklogical.StorageEntry{Key: oidcKeySetPath, Value: val}))
	}

	// A corrupt RETIRED key is dropped, not fatal.
	persist()
	tamperKid("retired", 0)
	loaded, err := loadKeySet(ctx, storage, fake, time.Second, core.logger)
	require.NoError(t, err, "a corrupt retired key must not fail the load")
	require.NotNil(t, loaded[oidcAlgRS256].active)
	assert.Empty(t, loaded[oidcAlgRS256].retired, "the corrupt retired key must be dropped")

	// A corrupt ACTIVE key fails the load loudly.
	persist()
	tamperKid("active", 0)
	_, err = loadKeySet(ctx, storage, fake, time.Second, core.logger)
	require.Error(t, err, "a corrupt active key must fail the load")
}

func TestCore_setupOIDCIssuer_RemoteToLocalCutover(t *testing.T) {
	core := createTestCore(t)
	defer core.tokenStore.Close()
	ctx := context.Background()

	fake := newFakeSignBackend(t)
	setupRemoteIssuer(t, core, fake)
	remoteActive, _, _, _ := loadRS256(ctx, NewBarrierView(core.barrier, oidcIssuerStorePrefix))
	require.NotNil(t, remoteActive)
	require.True(t, isRemoteSigningKey(remoteActive))
	remoteKid := remoteActive.kid

	// Simulate removing the signer stanza: drop the backend so setup selects the
	// local source, triggering a remote->local cutover.
	core.closeOIDCSignBackend()
	require.NoError(t, core.setupOIDCIssuer(ctx, false /* active */, false))

	iss := core.OIDCIssuer()
	require.True(t, iss.Ready(), "issuer must be ready after cutover")

	active, _, retired, _ := loadRS256(ctx, NewBarrierView(core.barrier, oidcIssuerStorePrefix))
	require.NotNil(t, active)
	assert.False(t, isRemoteSigningKey(active), "new active key must be local after remote->local cutover")

	// The old remote key was retired (kept for the grace window), still verifying.
	foundOld := false
	for _, r := range retired {
		if r.kid == remoteKid {
			foundOld = true
			assert.True(t, isRemoteSigningKey(r), "retired old key stays remote (verification-only)")
		}
	}
	assert.True(t, foundOld, "the old remote active key must be retained as retired")

	// The new local key mints and verifies.
	tok, err := iss.MintIdentityAssertion(ctx,
		&logical.TokenEntry{PrincipalID: "p", NamespaceID: "n", MountAccessor: "m"},
		AssertionClaims{Audience: "aud", TTL: time.Minute, Alg: oidcAlgRS256})
	require.NoError(t, err)
	assert.NotEmpty(t, tok)
}
