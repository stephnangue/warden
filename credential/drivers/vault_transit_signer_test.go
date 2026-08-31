package drivers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// signerKey is one key the fake store holds, with a public half a read returns.
type signerKey struct {
	keyType    string
	exportable bool
	versions   int
}

// transitSignerServer stands in for the store: a JWT login plus a transit key read. It
// records the login body and the token presented on the key read, which is how the
// tests check that the capability was minted under the spec's narrow role and used with
// the token that role issued.
type transitSignerServer struct {
	keys           map[string]signerKey
	loginBody      map[string]interface{}
	keyReadToken   string
	keyReadPath    string
	loginTTLSecond int
	// suppressAccessor models a role issuing untracked (batch) tokens, which carry no
	// accessor because the store never persists them.
	suppressAccessor bool
}

func newTransitSignerServer(t *testing.T, keys map[string]signerKey) (*transitSignerServer, string) {
	t.Helper()
	s := &transitSignerServer{keys: keys, loginTTLSecond: 900}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/auth/jwt/login" {
			_ = json.NewDecoder(r.Body).Decode(&s.loginBody)
			auth := map[string]interface{}{
				"client_token":   "hvs.capability",
				"accessor":       "acc-9",
				"lease_duration": s.loginTTLSecond,
				"policies":       []string{"default", "warden-tx-signer"},
			}
			if s.suppressAccessor {
				delete(auth, "accessor")
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"auth": auth})
			return
		}
		if name, ok := trimPrefixOK(r.URL.Path, "/v1/transit/keys/"); ok {
			s.keyReadToken = r.Header.Get("X-Vault-Token")
			s.keyReadPath = r.URL.Path
			k, found := s.keys[name]
			if !found {
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"errors": []string{"no such key"}})
				return
			}
			versions := map[string]interface{}{}
			for i := 1; i <= k.versions; i++ {
				versions[strconv.Itoa(i)] = map[string]interface{}{
					"public_key":    testPubPEM(t, k.keyType),
					"creation_time": time.Now().UTC().Format(time.RFC3339Nano),
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{
				"type":           k.keyType,
				"exportable":     k.exportable,
				"latest_version": k.versions,
				"keys":           versions,
			}})
			return
		}
		http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	return s, srv.URL
}

func trimPrefixOK(s, prefix string) (string, bool) {
	if len(s) > len(prefix) && s[:len(prefix)] == prefix {
		return s[len(prefix):], true
	}
	return "", false
}

func testPubPEM(t *testing.T, keyType string) string {
	t.Helper()
	var pub interface{}
	switch keyType {
	case "ecdsa-p256":
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		pub = &k.PublicKey
	case "ecdsa-p384":
		k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(t, err)
		pub = &k.PublicKey
	default:
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		pub = &k.PublicKey
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func transitSignerSpec(cfg map[string]string) *credential.CredSpec {
	base := map[string]string{
		"mint_method":       "transit_signer",
		"jwt_role":          "warden-transit-signer",
		"transit_key":       "client-assertion",
		"payload.client_id": "warden-gateway",
	}
	for k, v := range cfg {
		if v == "" {
			delete(base, k)
			continue
		}
		base[k] = v
	}
	return &credential.CredSpec{Name: "signer", Config: base}
}

func TestTransitSigner_MintsScopedCapability(t *testing.T) {
	srv, url := newTransitSignerServer(t, map[string]signerKey{
		"client-assertion": {keyType: "rsa-2048", versions: 3},
	})
	driver := federationDriver(t, url)

	rawData, metadata, ttl, leaseID, err := driver.MintCredentialWithExchange(
		context.TODO(), transitSignerSpec(nil), verifiedInputs())
	require.NoError(t, err)

	// The capability is minted under the SPEC's narrow role, not the source's broad
	// one — the whole security argument for the feature.
	assert.Equal(t, "warden-transit-signer", srv.loginBody["role"])
	assert.Equal(t, "hvs.capability", srv.keyReadToken, "the key is read with the token that role issued")

	assert.Equal(t, "transit", rawData["kms_backend"])
	assert.Equal(t, "hvs.capability", rawData["vault_token"])
	assert.Equal(t, url, rawData["vault_address"])
	assert.Equal(t, "transit", rawData["transit_mount"])
	assert.Equal(t, "client-assertion", rawData["transit_key"])
	assert.Equal(t, "RS256", rawData["signing_alg"])
	assert.Equal(t, "warden-gateway", rawData["client_id"], "payload.* travels unprefixed")

	// "Latest" is resolved to a concrete number here, so the held capability keeps
	// signing with the version that was validated rather than whatever is newest when
	// it eventually signs.
	assert.Equal(t, "3", rawData["transit_key_version"])
	assert.Equal(t, "client-assertion-v3", rawData["kid"], "kid names the exact version that will sign")
	assert.NotEmpty(t, rawData["token_expires_at"])

	assert.Equal(t, 900*time.Second, ttl, "the capability lives exactly as long as its token")
	assert.Empty(t, leaseID, "nothing to revoke: the token expires on its own")

	// What the role actually granted is recorded, since Warden cannot prove the policy
	// behind the name is as narrow as it should be.
	assert.Equal(t, "warden-transit-signer", metadata["role"])
	// Strings throughout: credential metadata is flattened to strings on parse, so a
	// slice or a number here would fail the mint rather than be coerced.
	assert.Equal(t, "default,warden-tx-signer", metadata["policies"])
	assert.Equal(t, "3", metadata["transit_key_version"])
}

// TestTransitSigner_RequiresSpecLevelRole is the guard that keeps the feature from
// being worse than what it replaces: inheriting the source's broad role would mint a
// capability with more reach than the private key it removes.
func TestTransitSigner_RequiresSpecLevelRole(t *testing.T) {
	_, url := newTransitSignerServer(t, map[string]signerKey{
		"client-assertion": {keyType: "rsa-2048", versions: 1},
	})
	driver := federationDriver(t, url)

	_, _, _, _, err := driver.MintCredentialWithExchange(
		context.TODO(), transitSignerSpec(map[string]string{"jwt_role": ""}), verifiedInputs())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "spec-level jwt_role")
	assert.Contains(t, err.Error(), "broader capability")
}

func TestTransitSigner_PinnedVersionAndExplicitKid(t *testing.T) {
	_, url := newTransitSignerServer(t, map[string]signerKey{
		"client-assertion": {keyType: "rsa-2048", versions: 4},
	})
	driver := federationDriver(t, url)

	rawData, _, _, _, err := driver.MintCredentialWithExchange(context.TODO(),
		transitSignerSpec(map[string]string{"transit_key_version": "2", "payload.kid": "operator-chosen"}),
		verifiedInputs())
	require.NoError(t, err)
	assert.Equal(t, "2", rawData["transit_key_version"])
	assert.Equal(t, "operator-chosen", rawData["kid"], "an explicit kid wins over the derived one")
}

func TestTransitSigner_RejectsUnusableKeys(t *testing.T) {
	_, url := newTransitSignerServer(t, map[string]signerKey{
		"client-assertion": {keyType: "rsa-2048", versions: 2},
		"exportable-key":   {keyType: "rsa-2048", versions: 1, exportable: true},
		"ec-key":           {keyType: "ecdsa-p384", versions: 1},
	})
	driver := federationDriver(t, url)

	cases := []struct {
		name   string
		cfg    map[string]string
		errMsg string
	}{
		{"unknown key", map[string]string{"transit_key": "nope"}, "unusable"},
		{"exportable key", map[string]string{"transit_key": "exportable-key"}, "exportable"},
		{"curve does not match alg", map[string]string{"transit_key": "ec-key", "signing_alg": "ES256"}, "expected"},
		{"version beyond latest", map[string]string{"transit_key_version": "9"}, "unusable"},
		{"non-numeric version", map[string]string{"transit_key_version": "latest"}, "positive integer"},
		{"missing client id", map[string]string{"payload.client_id": ""}, "payload.client_id"},
		{"missing key name", map[string]string{"transit_key": ""}, "transit_key is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, _, err := driver.MintCredentialWithExchange(
				context.TODO(), transitSignerSpec(tc.cfg), verifiedInputs())
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.errMsg)
		})
	}
}

// TestTransitSigner_TemplatedPerCaller: one source and one spec front a different client
// and a different non-exportable key per agent.
func TestTransitSigner_TemplatedPerCaller(t *testing.T) {
	_, url := newTransitSignerServer(t, map[string]signerKey{
		"tx-agent-7": {keyType: "rsa-2048", versions: 1},
	})
	driver := federationDriver(t, url)

	inputs := verifiedInputs()
	inputs.AgentClaims = map[string]string{"sub": "agent-7"}

	rawData, _, _, _, err := driver.MintCredentialWithExchange(context.TODO(),
		transitSignerSpec(map[string]string{
			"transit_key":       "tx-{{agent.sub}}",
			"payload.client_id": "client-{{agent.sub}}",
		}), inputs)
	require.NoError(t, err)
	assert.Equal(t, "tx-agent-7", rawData["transit_key"])
	assert.Equal(t, "client-agent-7", rawData["client_id"])
	assert.Equal(t, "tx-agent-7-v1", rawData["kid"], "a templated key yields a per-caller kid")
}

// TestTransitSigner_RefusedOffTheExchangePath: the capability is minted as the caller so
// it can be pinned to a narrow per-caller role. Served from the shared source session it
// would be neither.
func TestTransitSigner_RefusedOffTheExchangePath(t *testing.T) {
	_, url := newTransitSignerServer(t, map[string]signerKey{
		"client-assertion": {keyType: "rsa-2048", versions: 1},
	})
	driver := federationDriver(t, url)

	_, _, _, _, err := driver.MintCredential(context.TODO(), transitSignerSpec(nil))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "oidc_federation")
}

func TestTransitSigner_InfersKeyValueType(t *testing.T) {
	f := &VaultDriverFactory{}
	typ, err := f.InferCredentialType(map[string]string{"mint_method": "transit_signer"})
	require.NoError(t, err)
	assert.Equal(t, credential.TypeKeyValue, typ)
}

// TestTransitSigner_RecordsWhetherTheTokenIsTracked: an accessor means the store
// persisted the token, so each mint leaves one behind to expire. Warden records that
// rather than refusing it — the role's policy, not the token's shape, is what bounds
// the capability — but it must not pass unnoticed.
func TestTransitSigner_RecordsWhetherTheTokenIsTracked(t *testing.T) {
	keys := map[string]signerKey{"client-assertion": {keyType: "rsa-2048", versions: 1}}

	t.Run("untracked token", func(t *testing.T) {
		srv, url := newTransitSignerServer(t, keys)
		srv.suppressAccessor = true
		driver := federationDriver(t, url)

		_, metadata, _, _, err := driver.MintCredentialWithExchange(
			context.TODO(), transitSignerSpec(nil), verifiedInputs())
		require.NoError(t, err)
		assert.Equal(t, "false", metadata["tracked_token"])
		assert.NotContains(t, metadata, "accessor", "an untracked token has none to record")
	})

	t.Run("tracked token still mints", func(t *testing.T) {
		_, url := newTransitSignerServer(t, keys)
		driver := federationDriver(t, url)

		_, metadata, _, _, err := driver.MintCredentialWithExchange(
			context.TODO(), transitSignerSpec(nil), verifiedInputs())
		require.NoError(t, err, "a tracked token is an operational cost, not an error")
		assert.Equal(t, "true", metadata["tracked_token"])
		assert.Equal(t, "acc-9", metadata["accessor"])
	})
}

// TestTransitSigner_RejectsReservedPayloadNames: the bag is merged into the payload
// after the coordinates are written, so a name the driver owns would replace the real
// one — pointing the consumer at another address, or handing it a token this mint never
// obtained. Refused rather than dropped, so the spec cannot read as though it took.
func TestTransitSigner_RejectsReservedPayloadNames(t *testing.T) {
	_, url := newTransitSignerServer(t, map[string]signerKey{
		"client-assertion": {keyType: "rsa-2048", versions: 1},
	})
	driver := federationDriver(t, url)

	for _, key := range []string{"vault_token", "vault_address", "kms_backend", "transit_key", "transit_key_version", "signing_alg", "token_expires_at"} {
		t.Run(key, func(t *testing.T) {
			_, _, _, _, err := driver.MintCredentialWithExchange(context.TODO(),
				transitSignerSpec(map[string]string{"payload." + key: "attacker-supplied"}), verifiedInputs())
			require.Error(t, err)
			assert.Contains(t, err.Error(), "payload."+key)
			assert.Contains(t, err.Error(), "would replace it")
		})
	}
}

// TestTransitSigner_RoleCheckedBeforeLogin: the requirement exists to stop a broad token
// ever being minted, so it has to run before the login that would mint one. A check that
// ran inside the mint would refuse the capability only after obtaining it.
func TestTransitSigner_RoleCheckedBeforeLogin(t *testing.T) {
	srv, url := newTransitSignerServer(t, map[string]signerKey{
		"client-assertion": {keyType: "rsa-2048", versions: 1},
	})
	driver := federationDriver(t, url)

	_, _, _, _, err := driver.MintCredentialWithExchange(context.TODO(),
		transitSignerSpec(map[string]string{"jwt_role": ""}), verifiedInputs())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "spec-level jwt_role")
	assert.Nil(t, srv.loginBody, "no login was attempted, so no token was minted under the source's broad role")
}
