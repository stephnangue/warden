package drivers

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
)

// certEntra is an Entra ID token endpoint that authenticates apps by certificate the
// way Entra does: the assertion must be PS256 with a hash-length salt, name a
// registered certificate by x5t#S256 and carry no kid, and be addressed to this
// endpoint by and about the client. Anything else is answered as Entra answers it:
// 400 invalid_client, AADSTS700027.
type certEntra struct {
	*httptest.Server

	mu         sync.Mutex
	registered map[string]*rsa.PublicKey // x5t#S256 -> the certificate's key
	forms      []url.Values
	refusals   []string // why each refused assertion was refused
	calls      atomic.Int32
	// gate, when set, holds every token request until it is closed.
	gate chan struct{}
}

func newCertEntra(t *testing.T) *certEntra {
	t.Helper()
	e := &certEntra{registered: map[string]*rsa.PublicKey{}}
	e.Server = httptest.NewServer(http.HandlerFunc(e.serve))
	t.Cleanup(e.Close)
	return e
}

func (e *certEntra) register(c testClientCert) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.registered[x5tS256Of(c.leaf)] = &c.key.PublicKey
}

func (e *certEntra) lastForm(t *testing.T) url.Values {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	require.NotEmpty(t, e.forms, "no request reached Entra")
	return e.forms[len(e.forms)-1]
}

func (e *certEntra) serve(w http.ResponseWriter, r *http.Request) {
	e.calls.Add(1)
	if e.gate != nil {
		<-e.gate
	}
	_ = r.ParseForm()
	e.mu.Lock()
	e.forms = append(e.forms, r.PostForm)
	e.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	if reason := e.checkAssertion(r); reason != "" {
		e.mu.Lock()
		e.refusals = append(e.refusals, reason)
		e.mu.Unlock()
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"AADSTS700027: Client assertion failed signature validation.\r\nTrace ID: x","error_codes":[700027],"trace_id":"11111111-2222-3333-4444-555555555555"}`))
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":  fmt.Sprintf("tok-%d", e.calls.Load()),
		"expires_in":    3600,
		"token_type":    "Bearer",
		"refresh_token": "RT-must-not-leak",
	})
}

// checkAssertion returns why the request's client assertion is not acceptable, or "".
func (e *certEntra) checkAssertion(r *http.Request) string {
	f := r.PostForm
	if f.Get("client_secret") != "" {
		return "a client secret was sent"
	}
	if f.Get("client_assertion_type") != clientAssertionType {
		return "wrong client_assertion_type"
	}
	parts := strings.Split(f.Get("client_assertion"), ".")
	if len(parts) != 3 {
		return "not a compact JWS"
	}
	var hdr map[string]any
	if b, err := base64.RawURLEncoding.DecodeString(parts[0]); err != nil || json.Unmarshal(b, &hdr) != nil {
		return "unreadable header"
	}
	if hdr["alg"] != "PS256" {
		return fmt.Sprintf("alg %v", hdr["alg"])
	}
	if hdr["typ"] != "JWT" {
		return fmt.Sprintf("typ %v", hdr["typ"])
	}
	if _, ok := hdr["kid"]; ok {
		return "kid present"
	}
	x5t, _ := hdr["x5t#S256"].(string)
	e.mu.Lock()
	pub := e.registered[x5t]
	e.mu.Unlock()
	if pub == nil {
		return "certificate not registered"
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "unreadable signature"
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPSS(pub, crypto.SHA256, digest[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}) != nil {
		return "signature does not verify"
	}
	var claims map[string]any
	if b, err := base64.RawURLEncoding.DecodeString(parts[1]); err != nil || json.Unmarshal(b, &claims) != nil {
		return "unreadable claims"
	}
	clientID := f.Get("client_id")
	if claims["iss"] != clientID || claims["sub"] != clientID {
		return "iss/sub is not the client"
	}
	if claims["aud"] != e.URL+r.URL.Path {
		return fmt.Sprintf("aud %v", claims["aud"])
	}
	nbf, _ := claims["nbf"].(float64)
	exp, _ := claims["exp"].(float64)
	now := float64(time.Now().Unix())
	if nbf == 0 || exp == 0 || exp-nbf > 600 || now > exp || nbf > now+300 {
		return "bad validity window"
	}
	return ""
}

func testGatedLogger() *logger.GatedLogger {
	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	return log
}

// certSourceConfig is a certificate source pointed at login.
func certSourceConfig(c testClientCert, login string) map[string]string {
	return map[string]string{
		"auth_method":    azureAuthMethodCertificate,
		"tenant_id":      testAzureTenant,
		"client_id":      testAzureClient,
		"certificate":    c.certPEM,
		"private_key":    c.keyPEM,
		"login_endpoint": login,
	}
}

// newCertDriver builds a certificate source's driver the way the registry does.
func newCertDriver(t *testing.T, cfg map[string]string) *AzureDriver {
	t.Helper()
	drv, err := (&AzureDriverFactory{}).Create(credential.NewConfig(cfg), testGatedLogger())
	require.NoError(t, err)
	t.Cleanup(func() { _ = drv.Cleanup(context.Background()) })
	return drv.(*AzureDriver)
}

func TestAzureCertificate_ValidateConfig(t *testing.T) {
	factory := &AzureDriverFactory{}
	c := validTestClientCert(t)
	other := validTestClientCert(t)
	expired := newTestClientCert(t, time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))

	base := func(over map[string]string) credential.Config {
		cfg := map[string]string{
			"auth_method": azureAuthMethodCertificate,
			"tenant_id":   testAzureTenant,
			"client_id":   testAzureClient,
			"certificate": c.certPEM,
			"private_key": c.keyPEM,
		}
		for k, v := range over {
			if v == "" {
				delete(cfg, k)
				continue
			}
			cfg[k] = v
		}
		return credential.NewConfig(cfg)
	}

	require.NoError(t, factory.ValidateConfig(base(nil)))

	for name, tc := range map[string]struct {
		over map[string]string
		want string
	}{
		"no tenant":              {map[string]string{"tenant_id": ""}, "tenant_id and client_id are required"},
		"no client":              {map[string]string{"client_id": ""}, "tenant_id and client_id are required"},
		"no certificate":         {map[string]string{"certificate": ""}, "certificate is required"},
		"no key":                 {map[string]string{"private_key": ""}, "needs the certificate's private_key, or a secret_spec"},
		"key and secret_spec":    {map[string]string{"secret_spec": "signer"}, "private_key and secret_spec are exclusive"},
		"secret_field":           {map[string]string{"secret_field": "k"}, "secret_field is not supported on an azure source"},
		"key does not match":     {map[string]string{"private_key": other.keyPEM}, "does not match the certificate"},
		"expired":                {map[string]string{"certificate": expired.certPEM}, "expired at"},
		"leftover secret":        {map[string]string{"client_secret": "s"}, "must not be set for auth_method=certificate"},
		"leftover secret id":     {map[string]string{"secret_id": "22222222-2222-2222-2222-222222222222"}, "must not be set for auth_method=certificate"},
		"audience":               {map[string]string{"audience": "api://x"}, "only valid for auth_method=oidc_federation"},
		"secret_cache_ttl alone": {map[string]string{"secret_cache_ttl": "30m"}, "secret_cache_ttl applies only with secret_spec"},
		"certificate on static":  {map[string]string{"auth_method": azureAuthMethodStatic, "client_secret": "s", "secret_id": "22222222-2222-2222-2222-222222222222", "private_key": ""}, "certificate is only valid for auth_method=certificate"},
		"key on federation":      {map[string]string{"auth_method": azureAuthMethodOIDCFederation, "certificate": ""}, "private_key is only valid for auth_method=certificate"},
	} {
		t.Run(name, func(t *testing.T) {
			err := factory.ValidateConfig(base(tc.over))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}

	// A KMS-held key: the certificate and a secret_spec naming the signer, no key.
	require.NoError(t, factory.ValidateConfig(base(map[string]string{
		"private_key": "", "secret_spec": "signer", "secret_cache_ttl": "30m",
	})))

	// Only a certificate source chains, and only its key.
	err := factory.ValidateConfig(credential.NewConfig(map[string]string{
		"tenant_id": testAzureTenant, "client_id": testAzureClient,
		"client_secret": "s", "secret_id": "22222222-2222-2222-2222-222222222222",
		"secret_spec": "signer",
	}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret_spec is only valid for auth_method=certificate")
}

func TestAzureCertificate_RotationRefused(t *testing.T) {
	factory := &AzureDriverFactory{}
	c := validTestClientCert(t)
	err := factory.ValidateRotationConfig(credential.NewConfig(certSourceConfig(c, "")))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "roll the certificate over")

	entra := newCertEntra(t)
	entra.register(c)
	d := newCertDriver(t, certSourceConfig(c, entra.URL))
	assert.False(t, d.SupportsRotation(), "PrepareRotation would add a secret to an app that has none")
}

func TestAzureCertificate_StoredSecrets(t *testing.T) {
	c := validTestClientCert(t)
	assert.Equal(t, []string{"private_key"},
		(&AzureDriverFactory{}).StoredSecrets(credential.NewConfig(certSourceConfig(c, ""))))
}

// TestAzureCertificate_SourceToken is the feature: Create's probe and every source
// token authenticate with a PS256 assertion signed by the certificate's key, and no
// secret is ever sent.
func TestAzureCertificate_SourceToken(t *testing.T) {
	c := validTestClientCert(t)
	entra := newCertEntra(t)
	entra.register(c)

	d := newCertDriver(t, certSourceConfig(c, entra.URL))
	require.EqualValues(t, 1, entra.calls.Load(), "Create probes Entra with the certificate")

	form := entra.lastForm(t)
	assert.Equal(t, "client_credentials", form.Get("grant_type"))
	assert.Equal(t, testAzureClient, form.Get("client_id"))
	assert.Equal(t, armResource+".default", form.Get("scope"))
	assert.Empty(t, form.Get("client_secret"))
	claims := verifyCertAssertion(t, form.Get("client_assertion"), c.leaf)
	assert.Equal(t, entra.URL+"/"+testAzureTenant+"/oauth2/v2.0/token", claims["aud"])
	assert.Equal(t, testAzureClient, claims["iss"])
	assert.Equal(t, testAzureClient, claims["sub"])

	// The probe's token is cached; a different resource is a new, fresh assertion.
	tok, err := d.getSourceToken(context.Background(), armResource)
	require.NoError(t, err)
	assert.Equal(t, "tok-1", tok)
	_, err = d.getSourceToken(context.Background(), graphResource)
	require.NoError(t, err)
	require.EqualValues(t, 2, entra.calls.Load())
	second := entra.lastForm(t)
	assert.NotEqual(t, form.Get("client_assertion"), second.Get("client_assertion"), "every assertion is fresh")
	verifyCertAssertion(t, second.Get("client_assertion"), c.leaf)
}

// TestAzureCertificate_ConcurrentMissesCoalesce: concurrent misses for one resource
// share one assertion and one request, and racing Cleanup is safe.
func TestAzureCertificate_ConcurrentMissesCoalesce(t *testing.T) {
	c := validTestClientCert(t)
	entra := newCertEntra(t)
	entra.register(c)
	d := newCertDriver(t, certSourceConfig(c, entra.URL))
	base := entra.calls.Load()

	entra.mu.Lock()
	entra.gate = make(chan struct{})
	entra.mu.Unlock()

	var wg sync.WaitGroup
	tokens := make([]string, 20)
	for i := range tokens {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tok, err := d.getSourceToken(context.Background(), keyVaultResource)
			assert.NoError(t, err)
			tokens[i] = tok
		}(i)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = d.Cleanup(context.Background())
	}()
	require.Eventually(t, func() bool { return entra.calls.Load() > base }, 5*time.Second, 5*time.Millisecond)
	close(entra.gate)
	wg.Wait()

	assert.EqualValues(t, base+1, entra.calls.Load(), "one assertion, one request")
	for _, tok := range tokens {
		assert.Equal(t, tokens[0], tok)
	}
}

func TestAzureCertificate_Refusals(t *testing.T) {
	t.Run("unregistered certificate", func(t *testing.T) {
		c := validTestClientCert(t)
		entra := newCertEntra(t)
		_, err := (&AzureDriverFactory{}).Create(credential.NewConfig(certSourceConfig(c, entra.URL)), testGatedLogger())
		require.Error(t, err)
		msg := err.Error()
		assert.Contains(t, msg, "refused the certificate assertion of app "+testAzureClient)
		assert.Contains(t, msg, x5tS256Of(c.leaf))
		assert.Contains(t, msg, "acquireTokenWithCertificate")
		assert.Contains(t, msg, "AADSTS700027")
		assert.NotContains(t, msg, "Client assertion failed", "Entra's free text never reaches an error")
		assert.NotContains(t, msg, "\r")
		entra.mu.Lock()
		assert.Equal(t, []string{"certificate not registered"}, entra.refusals,
			"refused for the certificate alone: the assertion was otherwise well formed")
		entra.mu.Unlock()
	})

	t.Run("assertion outside its validity window blames the clock", func(t *testing.T) {
		ete := &entraTokenError{operation: acquireTokenWithCertificateOp, status: 400, code: "invalid_client", codes: []int{500133}}
		err := classifyEntraCertAuthError(ete, testAzureClient, "x5t")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "outside its validity window; check Warden's clock")
		assert.NotContains(t, err.Error(), "must be registered on the app")
	})

	t.Run("not yet valid", func(t *testing.T) {
		c := newTestClientCert(t, time.Now().Add(2*time.Minute), time.Now().Add(48*time.Hour))
		entra := newCertEntra(t)
		entra.register(c)
		_, err := (&AzureDriverFactory{}).Create(credential.NewConfig(certSourceConfig(c, entra.URL)), testGatedLogger())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "is not valid until")
		assert.EqualValues(t, 0, entra.calls.Load())
	})

	t.Run("expired certificate", func(t *testing.T) {
		c := newTestClientCert(t, time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))
		entra := newCertEntra(t)
		_, err := (&AzureDriverFactory{}).Create(credential.NewConfig(certSourceConfig(c, entra.URL)), testGatedLogger())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expired at")
		assert.EqualValues(t, 0, entra.calls.Load(), "an expired certificate never reaches Entra")
	})

	t.Run("expires while serving", func(t *testing.T) {
		c := validTestClientCert(t)
		entra := newCertEntra(t)
		entra.register(c)
		d := newCertDriver(t, certSourceConfig(c, entra.URL))
		before := entra.calls.Load()

		d.now = func() time.Time { return c.leaf.NotAfter.Add(time.Minute) }
		_, err := d.getSourceToken(context.Background(), graphResource)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "the source certificate (x5t#S256 "+x5tS256Of(c.leaf)+") expired at")
		assert.Equal(t, before, entra.calls.Load())
	})
}

// TestAzureCertificate_SpecRotation: a certificate source still rotates its specs'
// workload secrets, through a Graph token it obtains with the certificate.
func TestAzureCertificate_SpecRotation(t *testing.T) {
	c := validTestClientCert(t)
	stub := newAzureStub(t)
	var assertions []string
	var mu sync.Mutex
	stub.set(func(s *azureStub) {
		s.tokenHook = func(f url.Values) {
			mu.Lock()
			defer mu.Unlock()
			if f.Get("client_id") == testAzureClient {
				assertions = append(assertions, f.Get("client_assertion"))
			}
		}
	})
	cfg := certSourceConfig(c, stub.URL)
	d := newCertDriver(t, cfg)
	d.graphHost = stub.URL

	assert.True(t, d.SupportsSpecRotation())
	workload := "55555555-5555-5555-5555-555555555555"
	spec := &credential.CredSpec{Name: "s", Config: credential.NewConfig(map[string]string{
		"client_id": workload, "client_secret": "old", "secret_id": "66666666-6666-6666-6666-666666666666",
	})}
	_, _, _, err := d.PrepareSpecRotation(context.Background(), spec)
	require.NoError(t, err)
	assert.EqualValues(t, 1, stub.addCalls.Load())

	mu.Lock()
	defer mu.Unlock()
	require.NotEmpty(t, assertions)
	for _, a := range assertions {
		verifyCertAssertion(t, a, c.leaf)
	}
}

func TestAzureCertificate_OnBehalfOf(t *testing.T) {
	c := validTestClientCert(t)
	entra := newCertEntra(t)
	entra.register(c)
	d := newCertDriver(t, certSourceConfig(c, entra.URL))

	user := fakeJWT(t, map[string]any{"oid": "user-oid", "aud": testAzureClient})
	spec := oboSpec(nil)

	data, meta, _, _, err := d.MintCredentialWithExchange(context.Background(), spec, &credential.ExchangeInputs{SubjectToken: user})
	require.NoError(t, err)
	assert.NotEmpty(t, data["access_token"])
	assert.Equal(t, "user-oid", meta["subject"])
	assert.NotContains(t, fmt.Sprint(data, meta), "RT-must-not-leak")

	form := entra.lastForm(t)
	assert.Equal(t, oboGrantType, form.Get("grant_type"))
	assert.Equal(t, user, form.Get("assertion"), "the user's token is only ever the assertion")
	assert.Equal(t, oboRequestedTokenUse, form.Get("requested_token_use"))
	assert.Empty(t, form.Get("client_secret"))
	verifyCertAssertion(t, form.Get("client_assertion"), c.leaf)
	assert.NotEqual(t, user, form.Get("client_assertion"))

	t.Run("actor refused", func(t *testing.T) {
		_, _, _, _, err := d.MintCredentialWithExchange(context.Background(), spec,
			&credential.ExchangeInputs{SubjectToken: user, ActorToken: "warden.assertion"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "authenticates on_behalf_of with its certificate")
	})

	t.Run("another app refused", func(t *testing.T) {
		_, _, _, _, err := d.MintCredentialWithExchange(context.Background(),
			oboSpec(map[string]string{"client_id": "99999999-9999-9999-9999-999999999999"}),
			&credential.ExchangeInputs{SubjectToken: user})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must use the source's own app")
	})

	t.Run("refused certificate is explained", func(t *testing.T) {
		entra.mu.Lock()
		entra.registered = map[string]*rsa.PublicKey{}
		entra.mu.Unlock()
		_, _, _, _, err := d.MintCredentialWithExchange(context.Background(), spec, &credential.ExchangeInputs{SubjectToken: user})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "refused the certificate assertion of app "+testAzureClient)
		assert.Contains(t, err.Error(), x5tS256Of(c.leaf))
		assert.Contains(t, err.Error(), "acquireOnBehalfOf")
	})
}

func TestAzureCertificate_SpecErrorTreatsCertificateLikeStatic(t *testing.T) {
	c := validTestClientCert(t)
	src := credential.NewConfig(certSourceConfig(c, ""))
	ok := credential.NewConfig(map[string]string{
		"mint_method":                       azureMintMethodOnBehalfOf,
		credential.ConfigSubjectTokenSource: credential.SourceUserIdentity,
	})
	require.NoError(t, AzureOnBehalfOfSpecError(ok, src))

	withActor := credential.NewConfig(map[string]string{
		"mint_method":                       azureMintMethodOnBehalfOf,
		credential.ConfigSubjectTokenSource: credential.SourceUserIdentity,
		credential.ConfigActorTokenSource:   credential.SourceWardenIdentity,
	})
	err := AzureOnBehalfOfSpecError(withActor, src)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "own credential (client secret or certificate)")

	otherApp := credential.NewConfig(map[string]string{
		"mint_method":                       azureMintMethodOnBehalfOf,
		credential.ConfigSubjectTokenSource: credential.SourceUserIdentity,
		"client_id":                         "99999999-9999-9999-9999-999999999999",
	})
	require.Error(t, AzureOnBehalfOfSpecError(otherApp, src))
}

// TestAzureCertificate_ExpiryWarningIsRateLimited: the check that may log runs at most
// once per interval, whatever the request rate.
func TestAzureCertificate_ExpiryWarningIsRateLimited(t *testing.T) {
	c := newTestClientCert(t, time.Now().Add(-time.Hour), time.Now().Add(3*24*time.Hour))
	entra := newCertEntra(t)
	entra.register(c)
	d := newCertDriver(t, certSourceConfig(c, entra.URL))

	first := d.certWarnNext.Load()
	require.NotZero(t, first, "Create checks expiry")
	d.warnCertExpiry(time.Now())
	assert.Equal(t, first, d.certWarnNext.Load(), "no second check within the interval")
	d.warnCertExpiry(time.Now().Add(azureCertWarnInterval + time.Minute))
	assert.Greater(t, d.certWarnNext.Load(), first, "checked again once the interval has passed")
}
