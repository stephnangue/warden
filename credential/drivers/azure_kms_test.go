package drivers

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/credential/types"
)

// fakeKMS is a transit store holding one non-exportable RSA key, client-assertion:
// version 2 is the one a certificate was issued for, version 1 an older key. It signs
// as transit does — PSS unless pkcs1v15 is named, with the longest salt unless
// salt_length=hash — so a request that forgets the JWS salt length yields a signature
// Entra (and certEntra) refuse.
type fakeKMS struct {
	*httptest.Server
	key    *rsa.PrivateKey // version 2
	oldKey *rsa.PrivateKey // version 1

	mu         sync.Mutex
	signBodies []map[string]any
	tokens     []string // X-Vault-Token of each call
	signStatus int      // non-zero: refuse every sign with this status
	signCalls  atomic.Int32
	keyReads   atomic.Int32
}

func newFakeKMS(t *testing.T) *fakeKMS {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	oldKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	k := &fakeKMS{key: key, oldKey: oldKey}
	pubPEM := func(priv *rsa.PrivateKey) string {
		der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
		require.NoError(t, err)
		return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	}
	k.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		k.mu.Lock()
		k.tokens = append(k.tokens, r.Header.Get("X-Vault-Token"))
		k.mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/transit/keys/client-assertion":
			k.keyReads.Add(1)
			now := time.Now().Format(time.RFC3339Nano)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"type": "rsa-2048", "exportable": false, "latest_version": 2,
				"keys": map[string]any{
					"1": map[string]any{"public_key": pubPEM(oldKey), "creation_time": now},
					"2": map[string]any{"public_key": pubPEM(key), "creation_time": now},
				},
			}})
		case r.URL.Path == "/v1/transit/sign/client-assertion":
			k.signCalls.Add(1)
			var body map[string]any
			require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			k.mu.Lock()
			k.signBodies = append(k.signBodies, body)
			status := k.signStatus
			k.mu.Unlock()
			if status != 0 {
				w.WriteHeader(status)
				_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"permission denied"}})
				return
			}
			assert.Equal(t, true, body["prehashed"])
			assert.Equal(t, "sha2-256", body["hash_algorithm"])
			digest, err := base64.StdEncoding.DecodeString(body["input"].(string))
			require.NoError(t, err)
			ver := signedKeyVersion(body)
			signer := key
			if ver == 1 {
				signer = oldKey
			}
			var sig []byte
			if body["signature_algorithm"] == "pkcs1v15" {
				sig, err = rsa.SignPKCS1v15(rand.Reader, signer, crypto.SHA256, digest)
			} else {
				salt := rsa.PSSSaltLengthAuto
				if body["salt_length"] == "hash" {
					salt = rsa.PSSSaltLengthEqualsHash
				}
				sig, err = rsa.SignPSS(rand.Reader, signer, crypto.SHA256, digest, &rsa.PSSOptions{SaltLength: salt, Hash: crypto.SHA256})
			}
			require.NoError(t, err)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"signature":   "vault:v" + strconv.Itoa(ver) + ":" + base64.StdEncoding.EncodeToString(sig),
				"key_version": ver,
			}})
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusNotFound)
		}
	}))
	t.Cleanup(k.Close)
	return k
}

func (k *fakeKMS) lastSignBody(t *testing.T) map[string]any {
	t.Helper()
	k.mu.Lock()
	defer k.mu.Unlock()
	require.NotEmpty(t, k.signBodies, "nothing was signed")
	return k.signBodies[len(k.signBodies)-1]
}

// kmsMaterial is a PS256 capability for the fake's key, for the source's app.
func kmsMaterial(k *fakeKMS, over map[string]string) credential.SecretMaterial {
	o := map[string]string{"signing_alg": "PS256", "client_id": testAzureClient}
	for key, v := range over {
		o[key] = v
	}
	return capabilityMaterial(k.URL, o)
}

// kmsCertEnv is a certificate source whose key is held in kms, authenticating at
// entra and reading Key Vault at kv.
type kmsCertEnv struct {
	kms   *fakeKMS
	entra *certEntra
	kv    *kvStub
	cert  testClientCert
	d     *AzureDriver
}

func newKMSCertEnv(t *testing.T) *kmsCertEnv {
	t.Helper()
	kms := newFakeKMS(t)
	cert := issueTestClientCert(t, kms.key, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
	entra := newCertEntra(t)
	entra.register(cert)
	kv := newKVStub(t)
	kv.put("/secrets/datadog-keys", "dd-value", nil)

	d := newCertDriver(t, map[string]string{
		"auth_method":        azureAuthMethodCertificate,
		"tenant_id":          testAzureTenant,
		"client_id":          testAzureClient,
		"certificate":        cert.certPEM,
		"secret_spec":        "entra-signer",
		"login_endpoint":     entra.URL,
		"key_vault_endpoint": kv.URL,
	})
	return &kmsCertEnv{kms: kms, entra: entra, kv: kv, cert: cert, d: d}
}

// TestAzureKMS_OnBehalfOf is the feature: the app authenticates with an assertion its
// certificate key signs inside the KMS, and Warden never holds that key.
func TestAzureKMS_OnBehalfOf(t *testing.T) {
	env := newKMSCertEnv(t)
	assert.EqualValues(t, 0, env.entra.calls.Load(), "Create has no capability to probe with")

	user := fakeJWT(t, map[string]any{"oid": "user-oid", "aud": testAzureClient})
	data, meta, _, _, err := env.d.MintCredentialWithExchangeFromSecret(context.Background(), oboSpec(nil),
		&credential.ExchangeInputs{SubjectToken: user}, kmsMaterial(env.kms, nil))
	require.NoError(t, err)
	assert.NotEmpty(t, data["access_token"])
	assert.Equal(t, "user-oid", meta["subject"])

	form := env.entra.lastForm(t)
	assert.Equal(t, user, form.Get("assertion"))
	assert.Empty(t, form.Get("client_secret"))
	verifyCertAssertion(t, form.Get("client_assertion"), env.cert.leaf)

	body := env.kms.lastSignBody(t)
	assert.Equal(t, "pss", body["signature_algorithm"])
	assert.Equal(t, "hash", body["salt_length"], "never transit's maximum-salt default")
	assert.Equal(t, 2, signedKeyVersion(body), "the version the capability pins")
	assert.EqualValues(t, 1, env.kms.keyReads.Load(), "the key is checked against the certificate first")
	for _, tok := range env.kms.tokens {
		assert.Equal(t, "hvs.capability", tok, "the store is reached only with the capability's token")
	}
}

func TestAzureKMS_SecretRead(t *testing.T) {
	env := newKMSCertEnv(t)

	data, _, _, _, err := env.d.MintFromSecret(context.Background(), kvSpec(nil), kmsMaterial(env.kms, nil))
	require.NoError(t, err)
	assert.Equal(t, "dd-value", data["value"])
	verifyCertAssertion(t, env.entra.lastForm(t).Get("client_assertion"), env.cert.leaf)
	assert.Equal(t, keyVaultResource+".default", env.entra.lastForm(t).Get("scope"))

	// The Key Vault token and the key check are cached: a second read signs nothing.
	_, _, _, _, err = env.d.MintFromSecret(context.Background(), kvSpec(nil), kmsMaterial(env.kms, nil))
	require.NoError(t, err)
	assert.EqualValues(t, 1, env.entra.calls.Load())
	assert.EqualValues(t, 1, env.kms.signCalls.Load())
	assert.EqualValues(t, 1, env.kms.keyReads.Load())
}

func TestAzureKMS_Refusals(t *testing.T) {
	user := fakeJWT(t, map[string]any{"oid": "u"})
	obo := func(env *kmsCertEnv, material credential.SecretMaterial) error {
		_, _, _, _, err := env.d.MintCredentialWithExchangeFromSecret(context.Background(), oboSpec(nil),
			&credential.ExchangeInputs{SubjectToken: user}, material)
		return err
	}

	t.Run("key does not match the certificate", func(t *testing.T) {
		env := newKMSCertEnv(t)
		other := validTestClientCert(t)
		d := newCertDriver(t, map[string]string{
			"auth_method": azureAuthMethodCertificate, "tenant_id": testAzureTenant, "client_id": testAzureClient,
			"certificate": other.certPEM, "secret_spec": "entra-signer", "login_endpoint": env.entra.URL,
		})
		_, _, _, _, err := d.MintCredentialWithExchangeFromSecret(context.Background(), oboSpec(nil),
			&credential.ExchangeInputs{SubjectToken: user}, kmsMaterial(env.kms, nil))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not match the certificate")
		assert.Contains(t, err.Error(), `"client-assertion" version 2`)
		assert.ErrorIs(t, err, credential.ErrChainedSecretRejected, "a fresh capability may pin a key version that matches")
		assert.EqualValues(t, 0, env.kms.signCalls.Load(), "nothing is signed with a key the certificate does not name")
		assert.EqualValues(t, 0, env.entra.calls.Load())
	})

	// The case the sentinel exists for: a capability still pinned to the version
	// before the key was rotated and the source given the new version's certificate.
	// It is refused before anything is signed, the refetched capability pins the new
	// version, and each version is read once.
	t.Run("capability pinned to an older key version", func(t *testing.T) {
		env := newKMSCertEnv(t)
		err := obo(env, kmsMaterial(env.kms, map[string]string{"transit_key_version": "1"}))
		require.Error(t, err)
		assert.ErrorIs(t, err, credential.ErrChainedSecretRejected)
		assert.Contains(t, err.Error(), `"client-assertion" version 1`)
		assert.EqualValues(t, 0, env.kms.signCalls.Load())

		require.NoError(t, obo(env, kmsMaterial(env.kms, nil)))
		require.NoError(t, obo(env, kmsMaterial(env.kms, nil)))
		assert.EqualValues(t, 2, env.kms.keyReads.Load(), "one read per key version, then cached")
	})

	t.Run("capability for another app", func(t *testing.T) {
		env := newKMSCertEnv(t)
		err := obo(env, kmsMaterial(env.kms, map[string]string{"client_id": "99999999-9999-9999-9999-999999999999"}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "set payload.client_id")
		assert.NotErrorIs(t, err, credential.ErrChainedSecretRejected)
	})

	t.Run("capability not PS256", func(t *testing.T) {
		env := newKMSCertEnv(t)
		err := obo(env, kmsMaterial(env.kms, map[string]string{"signing_alg": "RS256"}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "signing_alg=PS256")
		assert.NotErrorIs(t, err, credential.ErrChainedSecretRejected)
		assert.EqualValues(t, 0, env.kms.signCalls.Load())
	})

	t.Run("expired capability is refetched", func(t *testing.T) {
		env := newKMSCertEnv(t)
		err := obo(env, kmsMaterial(env.kms, map[string]string{"token_expires_at": time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)}))
		require.Error(t, err)
		assert.ErrorIs(t, err, credential.ErrChainedSecretRejected)
		assert.EqualValues(t, 0, env.kms.signCalls.Load(), "a spent capability skips the round trip")
	})

	t.Run("store refuses the capability", func(t *testing.T) {
		env := newKMSCertEnv(t)
		env.kms.mu.Lock()
		env.kms.signStatus = http.StatusForbidden
		env.kms.mu.Unlock()
		err := obo(env, kmsMaterial(env.kms, nil))
		require.Error(t, err)
		assert.ErrorIs(t, err, credential.ErrChainedSecretRejected)
	})

	t.Run("Entra refusing the certificate is not refetched", func(t *testing.T) {
		env := newKMSCertEnv(t)
		env.entra.mu.Lock()
		env.entra.registered = map[string]*rsa.PublicKey{}
		env.entra.mu.Unlock()
		err := obo(env, kmsMaterial(env.kms, nil))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "refused the certificate assertion")
		assert.NotErrorIs(t, err, credential.ErrChainedSecretRejected,
			"an unregistered certificate stays unregistered; a refetch would only double every failing mint")
	})

	t.Run("bearer_token is not served", func(t *testing.T) {
		env := newKMSCertEnv(t)
		_, _, _, _, err := env.d.MintFromSecret(context.Background(), &credential.CredSpec{Name: "b",
			Config: credential.NewConfig(map[string]string{"mint_method": "bearer_token"})}, kmsMaterial(env.kms, nil))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "serves mint_method=secret_read and on_behalf_of")
	})

	t.Run("no capability, no signature", func(t *testing.T) {
		env := newKMSCertEnv(t)
		_, err := env.d.getSourceToken(context.Background(), graphResource)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "held in a KMS")
		assert.False(t, env.d.SupportsRotation())
		assert.False(t, env.d.SupportsSpecRotation(), "spec rotation runs without a mint, so without a capability")
		assert.EqualValues(t, 0, env.entra.calls.Load())
	})

	t.Run("a local-key source does not chain", func(t *testing.T) {
		c := validTestClientCert(t)
		entra := newCertEntra(t)
		entra.register(c)
		d := newCertDriver(t, certSourceConfig(c, entra.URL))
		_, _, _, _, err := d.MintFromSecret(context.Background(), kvSpec(nil), capabilityMaterial("http://unused", nil))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "only a certificate source whose key is held in a KMS chains")
	})
}

// TestAzureKMS_ThroughTheManager drives the chain the way a request does: the
// credential manager fetches the signing capability through the source's secret_spec
// and hands it to the azure driver. Delegated tokens are cached per user and never
// cross users; the capability is fetched once and reused; a Key Vault read rides the
// same source.
func TestAzureKMS_ThroughTheManager(t *testing.T) {
	env := newKMSCertEnv(t)
	log := testGatedLogger()

	typeRegistry := credential.NewTypeRegistry()
	require.NoError(t, typeRegistry.Register(types.NewKeyValueCredType()))
	require.NoError(t, typeRegistry.Register(types.NewAzureBearerTokenCredType()))
	driverRegistry := credential.NewDriverRegistry(log)
	require.NoError(t, driverRegistry.RegisterFactory(&AzureDriverFactory{}))
	require.NoError(t, driverRegistry.RegisterFactory(&LocalDriverFactory{}))

	// The signer: a local spec whose credential is the capability itself, as a
	// transit_signer spec would mint it.
	store := newChainStore()
	store.sources["signer-src"] = &credential.CredSource{Name: "signer-src", Type: credential.SourceTypeLocal, Config: credential.NewConfig(nil)}
	store.specs["entra-signer"] = &credential.CredSpec{
		Name: "entra-signer", Type: credential.TypeKeyValue, Source: "signer-src",
		Config: credential.NewConfig(kmsMaterial(env.kms, nil).Data),
	}
	store.sources["azure-kms"] = &credential.CredSource{
		Name: "azure-kms", Type: credential.SourceTypeAzure,
		Config: credential.NewConfig(map[string]string{
			"auth_method":               azureAuthMethodCertificate,
			"tenant_id":                 testAzureTenant,
			"client_id":                 testAzureClient,
			"certificate":               env.cert.certPEM,
			credential.ConfigSecretSpec: "entra-signer",
			"secret_cache_ttl":          "30m",
			"login_endpoint":            env.entra.URL,
			"key_vault_endpoint":        env.kv.URL,
		}),
	}
	store.specs["m365"] = &credential.CredSpec{Name: "m365", Type: credential.TypeAzureBearerToken, Source: "azure-kms", Config: oboSpec(nil).Config}
	store.specs["kv"] = &credential.CredSpec{Name: "kv", Type: credential.TypeKeyValue, Source: "azure-kms", Config: kvSpec(nil).Config}

	manager, err := credential.NewManager(typeRegistry, driverRegistry, store, log)
	require.NoError(t, err)

	// The signer is minted as the calling agent; a local spec needs no inputs.
	agent := credential.Caller{
		TokenID: "agent-token", TokenTTL: time.Hour,
		ResolveInputs: func(context.Context, string) (*credential.ExchangeInputs, error) { return nil, nil },
	}
	issueAs := func(user string) *credential.Credential {
		t.Helper()
		caller := agent
		caller.User = &credential.UserContext{TokenID: "user-token-" + user, TokenTTL: time.Hour}
		cred, err := manager.IssueCredential(chainNamespaceContext(), caller, "m365", &credential.ExchangeInputs{
			SubjectToken:     fakeJWT(t, map[string]any{"oid": user, "aud": testAzureClient}),
			SubjectTokenType: credential.TokenTypeJWT,
		})
		require.NoError(t, err)
		return cred
	}

	alice := issueAs("alice")
	again := issueAs("alice")
	bob := issueAs("bob")
	assert.Equal(t, alice.Data["access_token"], again.Data["access_token"], "one user's token is cached")
	assert.NotEqual(t, alice.Data["access_token"], bob.Data["access_token"], "and never served to another user")
	assert.EqualValues(t, 2, env.entra.calls.Load(), "one exchange per user")
	assert.EqualValues(t, 2, env.kms.signCalls.Load())
	assert.EqualValues(t, 1, env.kms.keyReads.Load(), "the key is checked once")
	verifyCertAssertion(t, env.entra.lastForm(t).Get("client_assertion"), env.cert.leaf)

	kvCred, err := manager.IssueCredential(chainNamespaceContext(), agent, "kv", nil)
	require.NoError(t, err)
	assert.Equal(t, "dd-value", kvCred.Data["value"])
}

// TestAzureKMS_ConcurrentMintsShareOneFlight: concurrent misses for one resource sign
// one assertion, with the capability of the caller that started the request; every
// caller gets the shared token, and the starter giving up does not fail the others.
func TestAzureKMS_ConcurrentMintsShareOneFlight(t *testing.T) {
	env := newKMSCertEnv(t)
	env.entra.mu.Lock()
	env.entra.gate = make(chan struct{})
	env.entra.mu.Unlock()

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderDone := make(chan error, 1)
	go func() {
		_, _, _, _, err := env.d.MintFromSecret(leaderCtx, kvSpec(nil),
			kmsMaterial(env.kms, map[string]string{"vault_token": "hvs.leader"}))
		leaderDone <- err
	}()
	require.Eventually(t, func() bool { return env.entra.calls.Load() == 1 }, 5*time.Second, 5*time.Millisecond)

	var wg sync.WaitGroup
	errs := make([]error, 10)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _, _, _, errs[i] = env.d.MintFromSecret(context.Background(), kvSpec(nil),
				kmsMaterial(env.kms, map[string]string{"vault_token": "hvs.caller-" + strconv.Itoa(i)}))
		}(i)
	}
	cancelLeader()
	assert.ErrorIs(t, <-leaderDone, context.Canceled, "the starter returns when its own context ends")
	close(env.entra.gate)
	wg.Wait()

	for i, err := range errs {
		assert.NoError(t, err, "caller %d", i)
	}
	assert.EqualValues(t, 1, env.entra.calls.Load(), "one assertion, one request")
	assert.EqualValues(t, 1, env.kms.signCalls.Load())
	env.kms.mu.Lock()
	defer env.kms.mu.Unlock()
	for _, tok := range env.kms.tokens {
		assert.Equal(t, "hvs.leader", tok, "the request was signed with the starter's capability alone")
	}
}
