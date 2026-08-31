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
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeSigningBackend stands in for the KMS: it reads a key and signs a prehashed
// digest with a key it holds, so an assertion it signs actually verifies.
type fakeSigningBackend struct {
	key           *rsa.PrivateKey
	signCalls     int
	signBody      map[string]interface{}
	signPath      string
	tokenSeen     string
	namespaceSeen string
	statusCode    int // when non-zero, the sign call fails with this status
}

func newFakeSigningBackend(t *testing.T) (*fakeSigningBackend, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	f := &fakeSigningBackend{key: key}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/transit/sign/") {
			f.signCalls++
			f.signPath = r.URL.Path
			f.tokenSeen = r.Header.Get("X-Vault-Token")
			f.namespaceSeen = r.Header.Get("X-Vault-Namespace")
			require.NoError(t, json.NewDecoder(r.Body).Decode(&f.signBody))
			if f.statusCode != 0 {
				w.WriteHeader(f.statusCode)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"errors": []string{"refused"}})
				return
			}
			digest, err := base64.StdEncoding.DecodeString(f.signBody["input"].(string))
			require.NoError(t, err)
			sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, digest)
			require.NoError(t, err)
			verInt := signedKeyVersion(f.signBody)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{
				"signature":   "vault:v" + strconv.Itoa(verInt) + ":" + base64.StdEncoding.EncodeToString(sig),
				"key_version": verInt,
			}})
			return
		}
		http.Error(w, "unexpected "+r.URL.Path, http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	return f, srv.URL
}

// signedKeyVersion reads the version the sign request pinned. JSON numbers decode as
// float64 here, so the fake must not assume otherwise.
func signedKeyVersion(body map[string]interface{}) int {
	switch v := body["key_version"].(type) {
	case float64:
		return int(v)
	case json.Number:
		n, _ := strconv.Atoi(v.String())
		return n
	}
	return 0
}

func (f *fakeSigningBackend) pubPEM(t *testing.T) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&f.key.PublicKey)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// capabilityMaterial is the payload the transit_signer mint method produces.
func capabilityMaterial(addr string, over map[string]string) credential.SecretMaterial {
	data := map[string]string{
		"kms_backend":         "transit",
		"vault_token":         "hvs.capability",
		"vault_address":       addr,
		"transit_mount":       "transit",
		"transit_key":         "client-assertion",
		"transit_key_version": "2",
		"signing_alg":         "RS256",
		"kid":                 "client-assertion-v2",
		"client_id":           "warden-gateway",
		"token_expires_at":    time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339),
	}
	for k, v := range over {
		if v == "" {
			delete(data, k)
			continue
		}
		data[k] = v
	}
	return credential.SecretMaterial{Data: data}
}

func kmsSourceConfig(tokenURL string) map[string]string {
	return map[string]string{
		"token_url":   tokenURL,
		"grant":       tokenExchangeGrantRFC8693,
		"client_auth": clientAuthKMSPrivateKeyJWT,
		"secret_spec": "idp-client-signer",
	}
}

// TestKMSAssertion_SignsRemotelyAndVerifies is the whole feature end to end: the
// assertion the authorization server receives is signed by a key this process never
// held, and it verifies against that key's public half.
func TestKMSAssertion_SignsRemotelyAndVerifies(t *testing.T) {
	kms, kmsURL := newFakeSigningBackend(t)

	var gotAssertion, gotClientID, gotAssertionType string
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		gotAssertion = r.Form.Get("client_assertion")
		gotClientID = r.Form.Get("client_id")
		gotAssertionType = r.Form.Get("client_assertion_type")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "downstream", "token_type": "Bearer", "expires_in": 1800,
		})
	}))
	defer sts.Close()

	d := newExchangeDriver(kmsSourceConfig(sts.URL), sts.Client())
	spec := &credential.CredSpec{Name: "s", Config: map[string]string{}}

	data, _, _, _, err := d.MintCredentialWithExchangeFromSecret(context.Background(), spec,
		subjectInputs(makeUnsignedJWT(map[string]interface{}{"sub": "u1"})),
		capabilityMaterial(kmsURL, nil))
	require.NoError(t, err)
	assert.Equal(t, "downstream", data["api_key"])

	// The signing request pinned the exact version and asked for the encoding the
	// crypto.Signer contract expects.
	assert.Equal(t, 1, kms.signCalls)
	assert.Equal(t, "/v1/transit/sign/client-assertion", kms.signPath)
	assert.Equal(t, "hvs.capability", kms.tokenSeen)
	assert.Equal(t, true, kms.signBody["prehashed"])
	assert.Equal(t, "pkcs1v15", kms.signBody["signature_algorithm"])
	assert.Equal(t, "sha2-256", kms.signBody["hash_algorithm"])
	assert.Equal(t, 2, signedKeyVersion(kms.signBody), "the sign request pinned the exact version")

	// What the endpoint saw is an ordinary private_key_jwt assertion.
	assert.Equal(t, "warden-gateway", gotClientID)
	assert.Equal(t, clientAssertionType, gotAssertionType)

	parts := strings.Split(gotAssertion, ".")
	require.Len(t, parts, 3)
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	var hdr map[string]string
	require.NoError(t, json.Unmarshal(headerJSON, &hdr))
	assert.Equal(t, "RS256", hdr["alg"])
	assert.Equal(t, "client-assertion-v2", hdr["kid"], "the kid names the version that signed")

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims map[string]interface{}
	require.NoError(t, json.Unmarshal(claimsJSON, &claims))
	assert.Equal(t, "warden-gateway", claims["iss"])
	assert.Equal(t, "warden-gateway", claims["sub"])
	assert.Equal(t, sts.URL, claims["aud"])
	assert.NotEmpty(t, claims["jti"])

	// The signature verifies against the key the KMS holds — which is the only proof
	// that the remote path produced a usable assertion rather than plausible bytes.
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	h := crypto.SHA256.New()
	h.Write([]byte(parts[0] + "." + parts[1]))
	require.NoError(t, rsa.VerifyPKCS1v15(&kms.key.PublicKey, crypto.SHA256, h.Sum(nil), sig))
	_ = kms.pubPEM(t)
}

// TestKMSAssertion_ExpiredCapabilitySkipsTheRoundTrip: a spent capability is recognised
// from what it already carries, and asks for a fresh one, without spending a call to
// find out.
func TestKMSAssertion_ExpiredCapabilitySkipsTheRoundTrip(t *testing.T) {
	kms, kmsURL := newFakeSigningBackend(t)
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "should not be reached", http.StatusInternalServerError)
	}))
	defer sts.Close()

	d := newExchangeDriver(kmsSourceConfig(sts.URL), sts.Client())
	_, _, _, _, err := d.MintCredentialWithExchangeFromSecret(context.Background(),
		&credential.CredSpec{Name: "s", Config: map[string]string{}},
		subjectInputs(makeUnsignedJWT(map[string]interface{}{"sub": "u1"})),
		capabilityMaterial(kmsURL, map[string]string{
			"token_expires_at": time.Now().Add(-time.Minute).UTC().Format(time.RFC3339),
		}))
	require.Error(t, err)
	assert.ErrorIs(t, err, credential.ErrChainedSecretRejected, "a spent capability is replaced, not retried")
	assert.Equal(t, 0, kms.signCalls, "no signing request is made for a capability known to be spent")
}

func TestKMSAssertion_SignFailureMapping(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		sentinel bool
	}{
		{"token refused", http.StatusForbidden, true},
		{"unauthorized", http.StatusUnauthorized, true},
		{"version fenced after rotation", http.StatusBadRequest, true},
		{"backend unwell", http.StatusInternalServerError, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kms, kmsURL := newFakeSigningBackend(t)
			kms.statusCode = tc.status
			sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "unreached", http.StatusInternalServerError)
			}))
			defer sts.Close()

			d := newExchangeDriver(kmsSourceConfig(sts.URL), sts.Client())
			_, _, _, _, err := d.MintCredentialWithExchangeFromSecret(context.Background(),
				&credential.CredSpec{Name: "s", Config: map[string]string{}},
				subjectInputs(makeUnsignedJWT(map[string]interface{}{"sub": "u1"})),
				capabilityMaterial(kmsURL, nil))
			require.Error(t, err)
			if tc.sentinel {
				assert.ErrorIs(t, err, credential.ErrChainedSecretRejected,
					"a refused capability should be replaced")
			} else {
				assert.NotErrorIs(t, err, credential.ErrChainedSecretRejected,
					"refetching cannot mend an unreachable backend, and must not evict a good capability")
			}
		})
	}
}

func TestKMSAssertion_MaterialExtraction(t *testing.T) {
	cases := []struct {
		name       string
		over       map[string]string
		errMsg     string
		incomplete bool
	}{
		{"missing token", map[string]string{"vault_token": ""}, "vault_token", true},
		{"missing address", map[string]string{"vault_address": ""}, "vault_address", true},
		{"missing mount", map[string]string{"transit_mount": ""}, "transit_mount", true},
		{"missing key", map[string]string{"transit_key": ""}, "transit_key", true},
		{"missing alg", map[string]string{"signing_alg": ""}, "signing_alg", true},
		{"missing version", map[string]string{"transit_key_version": ""}, "transit_key_version", true},
		{"missing backend", map[string]string{"kms_backend": ""}, "kms_backend", true},
		{"zero version", map[string]string{"transit_key_version": "0"}, "unusable key version", true},
		{"non-numeric version", map[string]string{"transit_key_version": "latest"}, "unusable key version", true},
		{"unknown backend", map[string]string{"kms_backend": "cloudkms"}, "unsupported signing backend", false},
		{"missing client id", map[string]string{"client_id": ""}, "no client id", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tokenExchangeChainedAuthFromMaterial(
				map[string]string{"client_auth": clientAuthKMSPrivateKeyJWT},
				capabilityMaterial("http://kms.example", tc.over))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.errMsg)
			if tc.incomplete {
				// A payload that could become complete — refetching may fix it.
				assert.ErrorIs(t, err, credential.ErrChainedSecretIncomplete)
			} else {
				// A build that cannot drive this backend. Refetching yields the same
				// answer, so it must not ask the manager to try again.
				assert.NotErrorIs(t, err, credential.ErrChainedSecretIncomplete)
			}
		})
	}
}

// TestKMSAssertion_IgnoresSecretField: the payload is read by fixed names, so a stray
// field selector must not be mistaken for "this one is the secret".
func TestKMSAssertion_IgnoresSecretField(t *testing.T) {
	material := capabilityMaterial("http://kms.example", nil)
	material.Field = "transit_key"

	auth, err := tokenExchangeChainedAuthFromMaterial(
		map[string]string{"client_auth": clientAuthKMSPrivateKeyJWT}, material)
	require.NoError(t, err)
	require.NotNil(t, auth.kms)
	assert.Equal(t, "client-assertion", auth.kms.keyName)
	assert.Empty(t, auth.secret, "no key material travels with a capability")
}

func TestKMSAssertion_ValidateConfig(t *testing.T) {
	f := &TokenExchangeDriverFactory{}
	base := func(over map[string]string) map[string]string {
		cfg := map[string]string{
			"token_url":   "https://idp.example.com/token",
			"client_auth": clientAuthKMSPrivateKeyJWT,
			"secret_spec": "idp-client-signer",
		}
		for k, v := range over {
			if v == "" {
				delete(cfg, k)
				continue
			}
			cfg[k] = v
		}
		return cfg
	}

	require.NoError(t, f.ValidateConfig(base(nil)))

	// A real key: the schema parses private_key before the client_auth arm runs, so a
	// junk value would be rejected for the wrong reason and prove nothing.
	pemKey := func() string {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		return string(pem.EncodeToMemory(&pem.Block{
			Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}))
	}()

	cases := []struct {
		name   string
		cfg    map[string]string
		errMsg string
	}{
		{"no secret_spec", base(map[string]string{"secret_spec": ""}), "requires secret_spec"},
		{"inline client_id", base(map[string]string{"client_id": "x"}), "must be omitted"},
		{"inline private_key", base(map[string]string{"private_key": pemKey}), "must be omitted"},
		{"inline kid", base(map[string]string{"client_assertion_kid": "k"}), "must be omitted"},
		{"secret_field", base(map[string]string{"secret_field": "f"}), "secret_field must be omitted"},
		{"assertion alg", base(map[string]string{"client_assertion_alg": "RS256"}), "client_assertion_alg must be omitted"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := f.ValidateConfig(tc.cfg)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.errMsg)
		})
	}
}

// multiKeySigningBackend signs for several named keys and records which capability
// token arrived against which key on every request.
type multiKeySigningBackend struct {
	mu     sync.Mutex
	keys   map[string]*rsa.PrivateKey
	paired map[string]string // key name -> the token that signed for it
	mixed  []string          // any request whose token did not belong to its key
}

func newMultiKeySigningBackend(t *testing.T, keyNames []string, tokenFor map[string]string) (*multiKeySigningBackend, string) {
	t.Helper()
	b := &multiKeySigningBackend{keys: map[string]*rsa.PrivateKey{}, paired: map[string]string{}}
	for _, name := range keyNames {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		b.keys[name] = k
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		name := strings.TrimPrefix(r.URL.Path, "/v1/transit/sign/")
		token := r.Header.Get("X-Vault-Token")

		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}

		b.mu.Lock()
		b.paired[name] = token
		if want, ok := tokenFor[name]; ok && token != want {
			// The whole point of the row: a token that belongs to a different
			// capability arrived against this key.
			b.mixed = append(b.mixed, fmt.Sprintf("key %s signed with token %q, want %q", name, token, want))
		}
		key := b.keys[name]
		b.mu.Unlock()

		if key == nil {
			http.Error(w, "no such key", http.StatusNotFound)
			return
		}
		digest, err := base64.StdEncoding.DecodeString(body["input"].(string))
		if err != nil {
			http.Error(w, "bad input", http.StatusBadRequest)
			return
		}
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
		if err != nil {
			http.Error(w, "sign failed", http.StatusInternalServerError)
			return
		}
		ver := signedKeyVersion(body)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{
			"signature":   "vault:v" + strconv.Itoa(ver) + ":" + base64.StdEncoding.EncodeToString(sig),
			"key_version": ver,
		}})
	}))
	t.Cleanup(srv.Close)
	return b, srv.URL
}

// TestKMSAssertion_ConcurrentSigningKeepsCapabilitiesApart pins the isolation the client
// pool depends on. One driver fronts many callers, and the base client for a given
// address is shared between them; only the per-assertion clone carries a token. If that
// clone were ever dropped — or the token set on the shared client — concurrent mints
// holding different capabilities would cross, and an assertion would be signed with the
// wrong key or refused outright.
//
// Each capability names its own key and carries its own token, so a crossing is directly
// observable at the backend rather than inferred.
func TestKMSAssertion_ConcurrentSigningKeepsCapabilitiesApart(t *testing.T) {
	const n = 24
	keyNames := make([]string, n)
	tokenFor := make(map[string]string, n)
	for i := 0; i < n; i++ {
		keyNames[i] = fmt.Sprintf("key-%02d", i)
		tokenFor[keyNames[i]] = fmt.Sprintf("hvs.token-%02d", i)
	}
	backend, url := newMultiKeySigningBackend(t, keyNames, tokenFor)

	// One driver, one pooled base client for this address — the shared state under test.
	d := newExchangeDriver(kmsSourceConfig("https://idp.example.com/token"), http.DefaultClient)

	var wg sync.WaitGroup
	errs := make([]error, n)
	assertions := make([]string, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			auth, err := tokenExchangeChainedAuthFromMaterial(
				map[string]string{"client_auth": clientAuthKMSPrivateKeyJWT},
				capabilityMaterial(url, map[string]string{
					"transit_key":         keyNames[i],
					"vault_token":         tokenFor[keyNames[i]],
					"transit_key_version": "1",
				}))
			if err != nil {
				errs[i] = err
				return
			}
			<-start // release them together, so the clones genuinely overlap
			assertions[i], errs[i] = d.signAssertionWithCapability(
				context.Background(), auth.kms, map[string]interface{}{"iss": "c", "sub": "c"})
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		require.NoError(t, err, "capability %d failed to sign", i)
		require.NotEmpty(t, assertions[i])
	}

	backend.mu.Lock()
	mixed := append([]string(nil), backend.mixed...)
	paired := len(backend.paired)
	backend.mu.Unlock()

	assert.Empty(t, mixed, "a capability's token reached another capability's key")
	assert.Equal(t, n, paired, "every capability signed with its own key")

	// And each assertion verifies against the key its own capability named — the proof
	// that the right key signed, not merely that the right token was presented.
	for i, a := range assertions {
		parts := strings.Split(a, ".")
		require.Len(t, parts, 3)
		sig, err := base64.RawURLEncoding.DecodeString(parts[2])
		require.NoError(t, err)
		h := crypto.SHA256.New()
		h.Write([]byte(parts[0] + "." + parts[1]))
		assert.NoError(t, rsa.VerifyPKCS1v15(&backend.keys[keyNames[i]].PublicKey, crypto.SHA256, h.Sum(nil), sig),
			"assertion %d was not signed by the key its capability named", i)
	}
}

// TestKMSAssertion_IgnoresAmbientEnvironment: the client that spends a capability must
// talk to the address the payload names and nowhere else. The API client's defaults read
// the process environment, and an agent address there is preferred over the configured
// one when the request is built — so an operator-set VAULT_AGENT_ADDR would otherwise
// divert a live capability token to whatever is listening there.
func TestKMSAssertion_IgnoresAmbientEnvironment(t *testing.T) {
	// A port nothing is listening on: if the client honoured it, the signing call would
	// fail to connect rather than reach the fake backend.
	t.Setenv("VAULT_AGENT_ADDR", "http://127.0.0.1:1")
	t.Setenv("VAULT_NAMESPACE", "someone-elses-tenant")
	t.Setenv("VAULT_TOKEN", "env-operator-token")

	kms, kmsURL := newFakeSigningBackend(t)
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"downstream","token_type":"Bearer","expires_in":1800}`))
	}))
	defer sts.Close()

	d := newExchangeDriver(kmsSourceConfig(sts.URL), sts.Client())
	_, _, _, _, err := d.MintCredentialWithExchangeFromSecret(context.Background(),
		&credential.CredSpec{Name: "s", Config: map[string]string{}},
		subjectInputs(makeUnsignedJWT(map[string]interface{}{"sub": "u1"})),
		capabilityMaterial(kmsURL, nil))
	require.NoError(t, err, "the signing call must reach the payload's address, not an ambient agent")
	assert.Equal(t, 1, kms.signCalls)
	assert.Equal(t, "hvs.capability", kms.tokenSeen,
		"the capability's own token signed, not one inherited from the environment")
	assert.Empty(t, kms.namespaceSeen,
		"the payload named no namespace, so none is sent")
}

// TestKMSAssertion_IDJAGSignsBothLegs: an ID-JAG exchange authenticates twice, at two
// different endpoints, inside one mint. Both legs must present an assertion signed by
// the capability, and each must be bound to the endpoint that receives it — an assertion
// replayed from leg 1 to leg 2 carries the wrong audience and a correct authorization
// server rejects it.
//
// Both legs share buildClientAssertion, so this guards against a future change that
// hoists the assertion out of the per-leg path and reuses one across both.
func TestKMSAssertion_IDJAGSignsBothLegs(t *testing.T) {
	kms, kmsURL := newFakeSigningBackend(t)

	var (
		mu      sync.Mutex
		byAud   = map[string]string{} // aud claim -> the assertion that carried it
		clients []string
	)
	recordLeg := func(t *testing.T, r *http.Request) {
		t.Helper()
		require.NoError(t, r.ParseForm())
		assertion := r.Form.Get("client_assertion")
		parts := strings.Split(assertion, ".")
		require.Len(t, parts, 3, "each leg must carry a signed assertion")
		claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
		require.NoError(t, err)
		var claims map[string]interface{}
		require.NoError(t, json.Unmarshal(claimsJSON, &claims))
		aud, _ := claims["aud"].(string)
		mu.Lock()
		byAud[aud] = assertion
		clients = append(clients, r.Form.Get("client_id"))
		mu.Unlock()
	}

	resSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recordLeg(t, r)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "final-access", "expires_in": 600})
	}))
	defer resSrv.Close()

	idpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recordLeg(t, r)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "the-id-jag", "issued_token_type": tokenTypeIDJAG, "expires_in": 300})
	}))
	defer idpSrv.Close()

	d := newExchangeDriver(map[string]string{
		"token_url":          idpSrv.URL,
		"resource_token_url": resSrv.URL,
		"grant":              tokenExchangeGrantIDJAG,
		"client_auth":        clientAuthKMSPrivateKeyJWT,
		"secret_spec":        "idp-client-signer",
	}, &http.Client{})
	spec := &credential.CredSpec{Config: map[string]string{"audience": "https://resource-as.example.com"}}

	rawData, _, _, _, err := d.MintCredentialWithExchangeFromSecret(context.Background(), spec,
		subjectInputs(makeUnsignedJWT(map[string]interface{}{"sub": "u1"})),
		capabilityMaterial(kmsURL, nil))
	require.NoError(t, err)
	assert.Equal(t, "final-access", rawData["api_key"])

	// One signature per leg: neither is reused, and neither leg went unauthenticated.
	assert.Equal(t, 2, kms.signCalls, "each leg signs its own assertion")

	mu.Lock()
	defer mu.Unlock()
	assert.Len(t, byAud, 2, "the two assertions carried different audiences")
	assert.Contains(t, byAud, idpSrv.URL, "leg 1's assertion is bound to the home endpoint")
	assert.Contains(t, byAud, resSrv.URL, "leg 2's assertion is bound to the resource endpoint")
	assert.NotEqual(t, byAud[idpSrv.URL], byAud[resSrv.URL], "an assertion must not be replayed across legs")
	assert.Equal(t, []string{"warden-gateway", "warden-gateway"}, clients, "both legs name the client the payload carries")
}
