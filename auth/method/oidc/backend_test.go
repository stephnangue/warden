package oidc

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"sync"
	"testing"
	"time"

	capoidc "github.com/hashicorp/cap/oidc"
	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/helper/selector"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// testSealer seals as core's sealer does: AES-GCM with the context
// "backend/<accessor>/<purpose>" as additional data.
type testSealer struct {
	gcm      cipher.AEAD
	accessor string
}

func newTestSealer(t *testing.T, key []byte, accessor string) *testSealer {
	t.Helper()
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)
	return &testSealer{gcm: gcm, accessor: accessor}
}

func (s *testSealer) aad(purpose string) []byte {
	return []byte("backend/" + s.accessor + "/" + purpose)
}

func (s *testSealer) Seal(_ context.Context, purpose string, pt []byte) ([]byte, error) {
	nonce := make([]byte, s.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return s.gcm.Seal(nonce, nonce, pt, s.aad(purpose)), nil
}

func (s *testSealer) Open(_ context.Context, purpose string, ct []byte) ([]byte, error) {
	if len(ct) < s.gcm.NonceSize() {
		return nil, errors.New("short")
	}
	return s.gcm.Open(nil, ct[:s.gcm.NonceSize()], ct[s.gcm.NonceSize():], s.aad(purpose))
}

func testLogger() *logger.GatedLogger {
	gl, _ := logger.NewGatedLogger(&logger.Config{Level: logger.ErrorLevel, Format: logger.JSONFormat, Outputs: []io.Writer{io.Discard}},
		logger.GatedWriterConfig{Underlying: io.Discard})
	return gl
}

const (
	testRedirect   = "http://127.0.0.1:53412/oidc/callback"
	testAccessor   = "auth_oidc_00000001"
	testClientID   = "warden-client"
	testSecret     = "warden-secret"
	testAuthCode   = "test-code"
	testMountPoint = "auth/oidc/"
)

// env is an oidc mount against a cap test identity provider.
type env struct {
	t       *testing.T
	ctx     context.Context
	tp      *capoidc.TestProvider
	b       *oidcAuthBackend
	key     []byte
	storage sdklogical.Storage
}

func newEnv(t *testing.T) *env {
	t.Helper()
	tp := capoidc.StartTestProvider(t)
	t.Cleanup(tp.Stop)
	tp.SetClientCreds(testClientID, testSecret)
	tp.SetAllowedRedirectURIs([]string{testRedirect})
	tp.SetExpectedAuthCode(testAuthCode)

	key := make([]byte, 32)
	_, _ = rand.Read(key)
	e := &env{t: t, ctx: namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace),
		tp: tp, key: key, storage: &sdklogical.InmemStorage{}}
	e.b = e.newBackend(testAccessor)
	return e
}

func (e *env) newBackend(accessor string) *oidcAuthBackend {
	e.t.Helper()
	raw, err := Factory(e.ctx, &logical.BackendConfig{
		Logger: testLogger(), StorageView: e.storage, Sealer: newTestSealer(e.t, e.key, accessor),
	})
	require.NoError(e.t, err)
	b := raw.(*oidcAuthBackend)
	require.NoError(e.t, b.Initialize(e.ctx))
	return b
}

func (e *env) alg() string {
	_, _, alg, _ := e.tp.SigningKeys()
	return string(alg)
}

// baseConfig is a working client_secret configuration for e's provider.
func (e *env) baseConfig() map[string]any {
	return map[string]any{
		"oidc_discovery_url":    e.tp.Addr(),
		"oidc_discovery_ca_pem": e.tp.CACert(),
		"client_id":             testClientID,
		"client_secret":         testSecret,
		"supported_algs":        []string{e.alg()},
		"allowed_redirect_uris": []string{"http://127.0.0.1/oidc/callback"},
		"facts": map[string]any{
			"oid":              "oid",
			"roles":            "roles",
			"/address/country": "country",
			"level":            "level",
			"admin":            "admin",
			"groups":           "groups",
		},
		"alias_name_source": "oid",
	}
}

func (e *env) call(b *oidcAuthBackend, path string, data map[string]any) *logical.Response {
	e.t.Helper()
	resp, err := b.HandleRequest(e.ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: path, Data: data,
		MountAccessor: testAccessor, MountPoint: testMountPoint, ClientIP: "10.0.0.1",
	})
	require.NoError(e.t, err)
	require.NotNil(e.t, resp)
	return resp
}

// configure writes the base config with over applied (a nil value drops the
// key).
func (e *env) configure(over map[string]any) *logical.Response {
	e.t.Helper()
	data := e.baseConfig()
	for k, v := range over {
		if v == nil {
			delete(data, k)
			continue
		}
		data[k] = v
	}
	return e.call(e.b, "config", data)
}

func (e *env) mustConfigure(over map[string]any) {
	e.t.Helper()
	resp := e.configure(over)
	require.NoError(e.t, resp.Err)
}

func (e *env) liveConfig(b *oidcAuthBackend) (*oidcConfig, *liveProvider) {
	b.configMu.RLock()
	defer b.configMu.RUnlock()
	return b.config, b.provider
}

// secret returns a login secret's binding and proof.
func secret() (binding, proof string) {
	s := make([]byte, 32)
	_, _ = rand.Read(s)
	h := sha256.Sum256(s)
	return base64.RawURLEncoding.EncodeToString(h[:]), base64.RawURLEncoding.EncodeToString(s)
}

// start runs auth_url and primes the test provider with the login's PKCE
// verifier and nonce, as a browser round trip would carry them.
func (e *env) start(b *oidcAuthBackend) (state, proof string) {
	e.t.Helper()
	binding, proof := secret()
	resp := e.call(b, "auth_url", map[string]any{"redirect_uri": testRedirect, "login_binding": binding})
	require.NoError(e.t, resp.Err)
	state = resp.Data["state"].(string)

	pending, err := b.openState(e.ctx, state, time.Now())
	require.NoError(e.t, err)
	v, err := capoidc.NewCodeVerifier(capoidc.WithVerifier(pending.Verifier))
	require.NoError(e.t, err)
	e.tp.SetPKCEVerifier(v)
	e.tp.SetExpectedAuthNonce(pending.Nonce)
	return state, proof
}

func (e *env) finish(b *oidcAuthBackend, state, proof string) *logical.Response {
	e.t.Helper()
	return e.call(b, "callback", map[string]any{"state": state, "code": testAuthCode, "login_proof": proof})
}

func (e *env) login(claims map[string]any) *logical.Response {
	e.t.Helper()
	e.tp.SetCustomClaims(claims)
	state, proof := e.start(e.b)
	return e.finish(e.b, state, proof)
}

func personClaims() map[string]any {
	return map[string]any{
		"oid":     "0583-oid",
		"roles":   []any{"Warden.Operator"},
		"address": map[string]any{"country": "CM"},
		"level":   float64(3),
		"admin":   true,
		"email":   "ada@example.com",
	}
}

func lookup(a *logical.Admission, n *logical.MountNaming, name string) []string {
	var out []string
	cur := a.Lookup(n, name)
	for {
		v, ok := cur.Next()
		if !ok {
			return out
		}
		out = append(out, string(selector.FormatScalar(nil, v)))
	}
}

// rsaKey returns an RSA key, its PEM and a self-signed certificate of it.
func rsaKey(t *testing.T) (*rsa.PrivateKey, string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "warden"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return key,
		string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})),
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestFactory_NeedsSealer(t *testing.T) {
	_, err := Factory(context.Background(), &logical.BackendConfig{Logger: testLogger()})
	assert.ErrorContains(t, err, "sealer")
}

func TestInitialize_PersistsAndReloads(t *testing.T) {
	e := newEnv(t)
	e.mustConfigure(nil)
	reloaded := e.newBackend(testAccessor)
	cfg, p := e.liveConfig(reloaded)
	require.NotNil(t, cfg)
	assert.NotNil(t, p)
	assert.Equal(t, testSecret, cfg.ClientSecret, "the secret is stored")
	assert.Equal(t, "oid", reloaded.mountFacts.Load().AliasSource)

	// An identity provider down at load is not a failed mount: the first
	// login builds the provider.
	e.tp.Stop()
	down := e.newBackend(testAccessor)
	cfg, p = e.liveConfig(down)
	assert.NotNil(t, cfg)
	assert.Nil(t, p)
}

// A stored config that fails validation is installed, readable, and refuses
// every login until it is rewritten.
func TestInitialize_InvalidStoredConfig(t *testing.T) {
	e := newEnv(t)
	e.mustConfigure(nil)
	entry, err := e.storage.Get(e.ctx, "config")
	require.NoError(t, err)
	var stored map[string]any
	require.NoError(t, entry.DecodeJSON(&stored))
	stored["session_ttl"] = int64(24 * time.Hour)
	bad, err := sdklogical.StorageEntryJSON("config", stored)
	require.NoError(t, err)
	require.NoError(t, e.storage.Put(e.ctx, bad))

	b := e.newBackend(testAccessor)
	cfg, p := e.liveConfig(b)
	require.NotNil(t, cfg)
	assert.Error(t, cfg.invalid)
	assert.Nil(t, p, "no provider is built for an invalid config")

	binding, _ := secret()
	resp := e.call(b, "auth_url", map[string]any{"redirect_uri": testRedirect, "login_binding": binding})
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.ErrorIs(t, resp.Err, errConfigInvalid)

	read, err := b.HandleRequest(e.ctx, &logical.Request{Operation: logical.ReadOperation, Path: "config"})
	require.NoError(t, err)
	assert.Equal(t, testClientID, read.Data["client_id"], "still readable")

	// A write merges onto the stored config, so it must fix what is invalid.
	e.b = b
	resp = e.configure(nil)
	assert.ErrorContains(t, resp.Err, "session_ttl", "the stored value is still refused")
	e.mustConfigure(map[string]any{"session_ttl": "1h"})
	cfg, _ = e.liveConfig(b)
	assert.NoError(t, cfg.invalid, "a write replaces it")
}

// A provider replaced by a config write is retired, and released only when
// the last login using it finishes.
func TestLive_ProviderLifecycle(t *testing.T) {
	e := newEnv(t)
	e.mustConfigure(nil)

	_, held, release, err := e.b.live(e.ctx)
	require.NoError(t, err)
	e.mustConfigure(map[string]any{"session_ttl": "2h"})
	_, current := e.liveConfig(e.b)
	assert.NotSame(t, held, current)

	held.mu.Lock()
	assert.True(t, held.retired)
	assert.Equal(t, 1, held.users, "still in use by the login that holds it")
	held.mu.Unlock()
	release()
	held.mu.Lock()
	assert.Zero(t, held.users)
	held.mu.Unlock()
}

// Logins racing config writes: run under -race.
func TestLive_ConcurrentWithConfigWrites(t *testing.T) {
	e := newEnv(t)
	e.mustConfigure(nil)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				_, p, release, err := e.b.live(e.ctx)
				if err == nil {
					_ = p.tokenURL
					release()
				}
			}
		}()
		if i%2 == 0 {
			e.mustConfigure(map[string]any{"session_ttl": "2h"})
		}
	}
	wg.Wait()
}
