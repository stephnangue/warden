package drivers

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// kmsOAuth2Config is an oauth2 source that signs its client assertions with a fetched
// signing capability.
func kmsOAuth2Config(tokenURL string) map[string]string {
	return map[string]string{
		"token_url":   tokenURL,
		"client_auth": clientAuthKMSPrivateKeyJWT,
		"secret_spec": "idp-client-signer",
	}
}

// verifyCapabilitySigned checks a compact JWS against pub and returns its header and
// claims.
func verifyCapabilitySigned(t *testing.T, assertion string, pub *rsa.PublicKey) (map[string]string, map[string]interface{}) {
	t.Helper()
	parts := strings.Split(assertion, ".")
	require.Len(t, parts, 3)
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	h := crypto.SHA256.New()
	h.Write([]byte(parts[0] + "." + parts[1]))
	require.NoError(t, rsa.VerifyPKCS1v15(pub, crypto.SHA256, h.Sum(nil), sig), "the assertion must verify against the key the KMS holds")

	var hdr map[string]string
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &hdr))
	var claims map[string]interface{}
	raw, err = base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &claims))
	return hdr, claims
}

func TestOAuth2DriverFactory_ValidateConfig_KMS(t *testing.T) {
	f := &OAuth2DriverFactory{}
	base := func(over map[string]string) credential.Config {
		cfg := kmsOAuth2Config("https://idp.example.com/token")
		for k, v := range over {
			if v == "" {
				delete(cfg, k)
				continue
			}
			cfg[k] = v
		}
		return credential.NewConfig(cfg)
	}

	require.NoError(t, f.ValidateConfig(base(nil)))
	require.NoError(t, f.ValidateConfig(base(map[string]string{"client_assertion_aud": "issuer", "issuer": "https://idp.example.com"})))
	require.NoError(t, f.ValidateConfig(base(map[string]string{"secret_cache_ttl": "5m"})))

	cases := []struct {
		name   string
		cfg    credential.Config
		errMsg string
	}{
		{"no secret_spec", base(map[string]string{"secret_spec": ""}), "requires secret_spec"},
		{"inline client_id", base(map[string]string{"client_id": "x"}), "client_id must be omitted when secret_spec is set"},
		{"inline secret", base(map[string]string{"client_secret": "x"}), "client_secret must be omitted when secret_spec is set"},
		{"inline private_key", base(map[string]string{"private_key": newOAuth2TestKey(t).pem}), "private_key must be omitted when secret_spec is set"},
		{"inline kid", base(map[string]string{"client_assertion_kid": "k"}), "client_assertion_kid must be omitted when secret_spec is set"},
		{"secret_field", base(map[string]string{"secret_field": "f"}), "secret_field must be omitted"},
		{"assertion alg", base(map[string]string{"client_assertion_alg": "RS256"}), "client_assertion_alg must be omitted"},
		{"issuer audience without an issuer", base(map[string]string{"client_assertion_aud": "issuer"}), "client_assertion_aud=issuer requires issuer"},
		{"the consent flow", base(map[string]string{"auth_method": "authorization_code"}), "auth_method=authorization_code is not supported when secret_spec is set"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := f.ValidateConfig(tc.cfg)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.errMsg)
		})
	}
}

// The whole feature: the assertion the token endpoint receives is signed by a key this
// process never held, names the client the capability's payload carries, and verifies
// against the key's public half.
func TestOAuth2Driver_KMS_SignsRemotelyAndVerifies(t *testing.T) {
	kms, kmsURL := newFakeSigningBackend(t)
	srv, received := newRecordingTokenEndpoint(t, oauth2BearerAnswer)
	d := newOAuth2DriverFromConfig(t, kmsOAuth2Config(srv.URL))
	t.Cleanup(func() { _ = d.Cleanup(context.Background()) })

	rawData, _, _, _, err := d.MintFromSecret(context.Background(),
		&credential.CredSpec{Name: "s", Config: credential.NewConfig(map[string]string{"scope": "read"})},
		capabilityMaterial(kmsURL, nil))
	require.NoError(t, err)
	assert.Equal(t, "at", rawData["api_key"])
	assert.Equal(t, 1, kms.signCalls)
	assert.Equal(t, "hvs.capability", kms.tokenSeen, "the capability's own token signed")

	reqs := received()
	require.Len(t, reqs, 1)
	form := reqs[0].form
	assert.Equal(t, "client_credentials", form.Get("grant_type"))
	assert.Equal(t, "read", form.Get("scope"))
	assert.Equal(t, "warden-gateway", form.Get("client_id"))
	assert.Equal(t, clientAssertionType, form.Get("client_assertion_type"))
	assert.Empty(t, form.Get("client_secret"))

	hdr, claims := verifyCapabilitySigned(t, form.Get("client_assertion"), &kms.key.PublicKey)
	assert.Equal(t, "RS256", hdr["alg"])
	assert.Equal(t, "client-assertion-v2", hdr["kid"], "the kid names the version that signed")
	assert.Equal(t, "warden-gateway", claims["iss"])
	assert.Equal(t, "warden-gateway", claims["sub"])
	assert.Equal(t, srv.URL, claims["aud"])
	assert.NotEmpty(t, claims["jti"])
}

// A spent capability is recognised from what it carries, and asks for a fresh one
// without spending a signing call or a token request to find out.
func TestOAuth2Driver_KMS_ExpiredCapabilitySkipsTheRoundTrip(t *testing.T) {
	kms, kmsURL := newFakeSigningBackend(t)
	srv, received := newRecordingTokenEndpoint(t, oauth2BearerAnswer)
	d := newOAuth2DriverFromConfig(t, kmsOAuth2Config(srv.URL))

	_, _, _, _, err := d.MintFromSecret(context.Background(), &credential.CredSpec{Name: "s", Config: credential.NewConfig(nil)},
		capabilityMaterial(kmsURL, map[string]string{
			"token_expires_at": time.Now().Add(-time.Minute).UTC().Format(time.RFC3339),
		}))
	require.Error(t, err)
	assert.ErrorIs(t, err, credential.ErrChainedSecretRejected, "a spent capability is replaced, not retried")
	assert.Contains(t, err.Error(), "the fetched signing capability expired")
	assert.Zero(t, kms.signCalls)
	assert.Empty(t, received())
}

func TestOAuth2Driver_KMS_SignFailureMapping(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		sentinel bool
	}{
		{"token refused", http.StatusForbidden, true},
		{"version fenced after rotation", http.StatusBadRequest, true},
		{"backend unwell", http.StatusInternalServerError, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kms, kmsURL := newFakeSigningBackend(t)
			kms.statusCode = tc.status
			srv, received := newRecordingTokenEndpoint(t, oauth2BearerAnswer)
			d := newOAuth2DriverFromConfig(t, kmsOAuth2Config(srv.URL))

			_, _, _, _, err := d.MintFromSecret(context.Background(), &credential.CredSpec{Name: "s", Config: credential.NewConfig(nil)},
				capabilityMaterial(kmsURL, nil))
			require.Error(t, err)
			if tc.sentinel {
				assert.ErrorIs(t, err, credential.ErrChainedSecretRejected, "a refused capability should be replaced")
			} else {
				assert.NotErrorIs(t, err, credential.ErrChainedSecretRejected,
					"refetching cannot mend an unreachable backend, and must not evict a good capability")
			}
			status, ok := credential.UpstreamStatus(err)
			assert.True(t, ok, "the store's status must survive: %v", err)
			assert.Equal(t, tc.status, status)
			assert.Empty(t, received(), "nothing is sent without a signed assertion")
		})
	}
}

// A payload that is not a usable capability is refetched once, in case it predates a
// coordinate it now has to carry.
func TestOAuth2Driver_KMS_IncompleteCapabilityIsRefetched(t *testing.T) {
	d := newOAuth2DriverFromConfig(t, kmsOAuth2Config("https://idp.example.com/token"))
	_, _, _, _, err := d.MintFromSecret(context.Background(), &credential.CredSpec{Name: "s", Config: credential.NewConfig(nil)},
		capabilityMaterial("http://kms.example", map[string]string{"transit_key": ""}))
	require.Error(t, err)
	assert.ErrorIs(t, err, credential.ErrChainedSecretIncomplete)
}

// The payload is read by fixed names. A secret_field a spec resolved — the source is
// refused one, a spec is not — must not be mistaken for "this coordinate is the secret".
func TestOAuth2Driver_KMS_IgnoresSecretField(t *testing.T) {
	kms, kmsURL := newFakeSigningBackend(t)
	srv, received := newRecordingTokenEndpoint(t, oauth2BearerAnswer)
	d := newOAuth2DriverFromConfig(t, kmsOAuth2Config(srv.URL))

	material := capabilityMaterial(kmsURL, nil)
	material.Field = "vault_token"
	_, _, _, _, err := d.MintFromSecret(context.Background(), &credential.CredSpec{Name: "s", Config: credential.NewConfig(nil)}, material)
	require.NoError(t, err)
	assert.Equal(t, 1, kms.signCalls)
	_, claims := verifyCapabilitySigned(t, received()[0].form.Get("client_assertion"), &kms.key.PublicKey)
	assert.Equal(t, "warden-gateway", claims["sub"])
}

// Moving a source to kms_private_key_jwt clears what that method refuses, so the planned
// config validates.
func TestKeylessPlan_MovingToKMSClearsWhatItRefuses(t *testing.T) {
	inputs := map[string]string{"client_auth": clientAuthKMSPrivateKeyJWT, credential.ConfigSecretSpec: "idp-client-signer"}
	current := credential.NewConfig(map[string]string{
		"token_url": "https://idp.example.com/token", "client_auth": clientAuthPrivateKeyJWT,
		"client_id": "c", "private_key": newOAuth2TestKey(t).pem, "client_assertion_kid": "k", "client_assertion_alg": "RS256",
	})

	for name, plan := range map[string]func() (*credential.KeylessSourcePlan, error){
		"oauth2": func() (*credential.KeylessSourcePlan, error) {
			return (&OAuth2DriverFactory{}).PlanKeyless(current, inputs)
		},
		"token_exchange": func() (*credential.KeylessSourcePlan, error) {
			return (&TokenExchangeDriverFactory{}).PlanKeyless(current, inputs)
		},
	} {
		t.Run(name, func(t *testing.T) {
			p, err := plan()
			require.NoError(t, err)
			v, ok := p.Delta["client_assertion_alg"]
			assert.True(t, ok && v == "", "client_assertion_alg is cleared")

			// Apply the delta and validate what results.
			merged := map[string]string{}
			for k, v := range current.All() {
				merged[k] = v
			}
			for k, v := range p.Delta {
				if v == "" {
					delete(merged, k)
				} else {
					merged[k] = v
				}
			}
			var verr error
			if name == "oauth2" {
				verr = (&OAuth2DriverFactory{}).ValidateConfig(credential.NewConfig(merged))
			} else {
				verr = (&TokenExchangeDriverFactory{}).ValidateConfig(credential.NewConfig(merged))
			}
			assert.NoError(t, verr, "the planned config validates: %v", merged)
		})
	}
}

// A source that signs with a capability has nothing to sign with outside the chain.
func TestOAuth2Driver_KMS_DirectMintIsRefused(t *testing.T) {
	d := newOAuth2DriverFromConfig(t, kmsOAuth2Config("https://idp.example.com/token"))
	_, _, _, _, err := d.MintCredential(context.Background(), &credential.CredSpec{Name: "s", Config: credential.NewConfig(nil)})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "uses secret_spec (credential chaining)")
}

// A retry signs afresh with the capability, so a server that spent the first assertion
// does not refuse the second as a replay.
func TestOAuth2Driver_KMS_RetryPresentsAFreshAssertion(t *testing.T) {
	kms, kmsURL := newFakeSigningBackend(t)
	as := newSingleUseAS(t, loseAnswerToDrop, oauth2BearerAnswer)
	d := newOAuth2DriverFromConfig(t, kmsOAuth2Config(as.srv.URL))

	_, _, _, _, err := d.MintFromSecret(context.Background(), &credential.CredSpec{Name: "s", Config: credential.NewConfig(nil)},
		capabilityMaterial(kmsURL, nil))
	require.NoError(t, err, "the retry must not be refused as a replay")
	assertTwoDistinctJTIs(t, as.received())
	assert.Equal(t, 2, kms.signCalls, "each attempt is signed afresh")
}

// One driver fronts many callers. Concurrent mints holding different capabilities must
// each sign with their own key and name their own client.
func TestOAuth2Driver_KMS_ConcurrentMintsKeepCapabilitiesApart(t *testing.T) {
	const n = 16
	keyNames := make([]string, n)
	tokenFor := make(map[string]string, n)
	for i := 0; i < n; i++ {
		keyNames[i] = fmt.Sprintf("key-%02d", i)
		tokenFor[keyNames[i]] = fmt.Sprintf("hvs.token-%02d", i)
	}
	backend, kmsURL := newMultiKeySigningBackend(t, keyNames, tokenFor)
	srv, received := newRecordingTokenEndpoint(t, oauth2BearerAnswer)
	d := newOAuth2DriverFromConfig(t, kmsOAuth2Config(srv.URL))
	t.Cleanup(func() { _ = d.Cleanup(context.Background()) })

	var wg sync.WaitGroup
	errs := make([]error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, _, _, _, errs[i] = d.MintFromSecret(context.Background(), &credential.CredSpec{Name: "s", Config: credential.NewConfig(nil)},
				capabilityMaterial(kmsURL, map[string]string{
					"transit_key":         keyNames[i],
					"vault_token":         tokenFor[keyNames[i]],
					"transit_key_version": "1",
					"client_id":           fmt.Sprintf("client-%02d", i),
				}))
		}(i)
	}
	close(start)
	wg.Wait()
	for i, err := range errs {
		require.NoError(t, err, "mint %d", i)
	}

	backend.mu.Lock()
	mixed := append([]string(nil), backend.mixed...)
	backend.mu.Unlock()
	assert.Empty(t, mixed, "a capability's token reached another capability's key")

	reqs := received()
	require.Len(t, reqs, n)
	for _, req := range reqs {
		var i int
		_, err := fmt.Sscanf(req.form.Get("client_id"), "client-%02d", &i)
		require.NoError(t, err)
		_, claims := verifyCapabilitySigned(t, req.form.Get("client_assertion"), &backend.keys[keyNames[i]].PublicKey)
		assert.Equal(t, req.form.Get("client_id"), claims["sub"], "the assertion names the client its capability carries")
	}
}

// The signing store's connections are pooled per driver, so the driver releases them
// when it is replaced or removed.
func TestOAuth2Driver_KMS_CleanupClosesSigningConnections(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	var closed atomic.Int32
	kms := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		digest, err := base64.StdEncoding.DecodeString(body["input"].(string))
		require.NoError(t, err)
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
		require.NoError(t, err)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{
			"signature":   "vault:v2:" + base64.StdEncoding.EncodeToString(sig),
			"key_version": 2,
		}})
	}))
	kms.Config.ConnState = func(_ net.Conn, st http.ConnState) {
		if st == http.StateClosed {
			closed.Add(1)
		}
	}
	kms.Start()
	defer kms.Close()

	srv, _ := newRecordingTokenEndpoint(t, oauth2BearerAnswer)
	d := newOAuth2DriverFromConfig(t, kmsOAuth2Config(srv.URL))

	_, _, _, _, err = d.MintFromSecret(context.Background(), &credential.CredSpec{Name: "s", Config: credential.NewConfig(nil)},
		capabilityMaterial(kms.URL, nil))
	require.NoError(t, err)
	require.Zero(t, closed.Load(), "the signing connection is kept for reuse")

	require.NoError(t, d.Cleanup(context.Background()))
	require.Eventually(t, func() bool { return closed.Load() > 0 }, 2*time.Second, 10*time.Millisecond,
		"Cleanup must close the pooled signing connections")
}

func TestOAuth2DriverFactory_KeylessPrerequisites_KMS(t *testing.T) {
	prereqs := (&OAuth2DriverFactory{}).KeylessPrerequisites(credential.NewConfig(kmsOAuth2Config("https://idp.example.com/token")), nil, credential.TrustEnv{})
	require.Len(t, prereqs, 1)
	assert.Contains(t, prereqs[0].Body, "a signing capability")
	assert.NotContains(t, prereqs[0].Body, "client_secret")
}
