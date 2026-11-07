package helpers

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zalando/go-keyring"

	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/helper/dpop"
)

const clientTestAddr = "https://warden.example:8400"

// newSessionClient builds Client() afresh under env, with sessions in a
// temporary directory, and returns it and what it wrote on stderr.
func newSessionClient(t *testing.T, env map[string]string) (*api.Client, string) {
	t.Helper()
	for _, k := range []string{api.EnvWardenToken, api.EnvWardenRole, api.EnvWardenNamespace, EnvSessionKeystore} {
		t.Setenv(k, "")
	}
	t.Setenv(api.EnvWardenAddress, clientTestAddr)
	for k, v := range env {
		t.Setenv(k, v)
	}
	stderr := &bytes.Buffer{}
	SetErrorWriter(stderr)
	SetTestClient(nil)
	t.Cleanup(func() {
		SetTestClient(nil)
		ResetWriters()
	})
	client, err := Client()
	require.NoError(t, err)
	return client, stderr.String()
}

func saveTestSession(t *testing.T, ns, role string, ttl time.Duration) *Session {
	t.Helper()
	addr, err := NormalizeAddr(clientTestAddr)
	require.NoError(t, err)
	s := &Session{Addr: addr, Namespace: ns, Mount: "auth/oidc/", Token: "wdt.session-" + ns, Role: role,
		ExpiresAt: time.Now().Add(ttl)}
	require.NoError(t, SaveSession(s))
	return s
}

func TestClient_SessionPrecedence(t *testing.T) {
	useSessionDir(t)
	saveTestSession(t, "", "operator", time.Hour)

	t.Run("the session's ticket and role", func(t *testing.T) {
		client, _ := newSessionClient(t, nil)
		assert.Equal(t, "wdt.session-", client.Token())
		assert.Equal(t, "operator", client.Headers().Get(api.RoleHeaderName))
		require.NotNil(t, CurrentSession())
	})

	t.Run("WARDEN_ROLE beats the session's role", func(t *testing.T) {
		client, _ := newSessionClient(t, map[string]string{api.EnvWardenRole: "auditor"})
		assert.Equal(t, "wdt.session-", client.Token())
		assert.Equal(t, "auditor", client.Headers().Get(api.RoleHeaderName))
	})

	t.Run("WARDEN_TOKEN beats the session, whose role is then never sent", func(t *testing.T) {
		client, _ := newSessionClient(t, map[string]string{api.EnvWardenToken: "wds.root"})
		assert.Equal(t, "wds.root", client.Token())
		assert.Empty(t, client.Headers().Get(api.RoleHeaderName))
		assert.Nil(t, CurrentSession())
	})

	t.Run("a JWT in WARDEN_TOKEN beats the session too", func(t *testing.T) {
		client, _ := newSessionClient(t, map[string]string{api.EnvWardenToken: "eyJhbGciOiJSUzI1NiJ9.e30.sig"})
		assert.Empty(t, client.Token())
		assert.Equal(t, "Bearer eyJhbGciOiJSUzI1NiJ9.e30.sig", client.Headers().Get("Authorization"))
		assert.Empty(t, client.Headers().Get(api.RoleHeaderName))
	})
}

func TestClient_ExpiredSessionNotSent(t *testing.T) {
	useSessionDir(t)
	saveTestSession(t, "", "operator", -time.Minute)
	client, stderr := newSessionClient(t, nil)
	assert.Empty(t, client.Token())
	assert.Empty(t, client.Headers().Get(api.RoleHeaderName))
	assert.Contains(t, stderr, "session expired; run warden login")
	assert.Nil(t, CurrentSession())
}

func TestClient_ParentSessionFallback(t *testing.T) {
	useSessionDir(t)
	saveTestSession(t, "team-a", "operator", time.Hour)

	client, stderr := newSessionClient(t, map[string]string{api.EnvWardenNamespace: "team-a/dev"})
	assert.Equal(t, "wdt.session-team-a", client.Token())
	assert.Equal(t, "team-a/dev", client.Namespace(), "the request keeps its own namespace")
	assert.Contains(t, stderr, "using session from namespace team-a")

	saveTestSession(t, "team-a/dev", "auditor", time.Hour)
	client, stderr = newSessionClient(t, map[string]string{api.EnvWardenNamespace: "team-a/dev"})
	assert.Equal(t, "wdt.session-team-a/dev", client.Token(), "an exact session wins")
	assert.NotContains(t, stderr, "using session from")

	client, _ = newSessionClient(t, map[string]string{api.EnvWardenNamespace: "team-b"})
	assert.Empty(t, client.Token(), "never a sibling's session")
}

// A session store that cannot be used never fails a command: it is skipped,
// with a warning when there is something to warn about.
func TestClient_BrokenSessionStore(t *testing.T) {
	t.Run("no home directory", func(t *testing.T) {
		SetSessionDir("")
		t.Setenv("HOME", "")
		client, stderr := newSessionClient(t, nil)
		assert.Empty(t, client.Token())
		assert.Empty(t, stderr, "nothing to warn about")
	})

	t.Run("a corrupt ancestor session", func(t *testing.T) {
		dir := useSessionDir(t)
		addr, err := NormalizeAddr(clientTestAddr)
		require.NoError(t, err)
		require.NoError(t, os.MkdirAll(dir, 0o700))
		require.NoError(t, os.WriteFile(sessionPath(dir, addr, ""), []byte("{not json"), 0o600))
		client, stderr := newSessionClient(t, map[string]string{api.EnvWardenNamespace: "team-a/dev"})
		assert.Empty(t, client.Token())
		assert.Contains(t, stderr, "session not used")
	})

	t.Run("a symlinked session directory", func(t *testing.T) {
		linked := filepath.Join(t.TempDir(), "sessions")
		require.NoError(t, os.Symlink(t.TempDir(), linked))
		SetSessionDir(linked)
		t.Cleanup(func() { SetSessionDir("") })
		client, stderr := newSessionClient(t, nil)
		assert.Empty(t, client.Token())
		assert.Contains(t, stderr, "symbolic link")
	})

	t.Run("a session that cannot be sent as a header", func(t *testing.T) {
		useSessionDir(t)
		s := saveTestSession(t, "", "oper\nator", time.Hour)
		require.NoError(t, SaveSession(s))
		client, stderr := newSessionClient(t, nil)
		assert.Empty(t, client.Token())
		assert.Contains(t, stderr, "control character")
	})
}

// A configured client certificate is an explicit credential: the session is
// not added beside it.
func TestClient_ClientCertBeatsSession(t *testing.T) {
	useSessionDir(t)
	saveTestSession(t, "", "operator", time.Hour)
	client := mustBareClient(t)
	t.Setenv(api.EnvWardenToken, "")
	t.Setenv(api.EnvWardenClientCert, filepath.Join(t.TempDir(), "cert.pem"))
	assert.NoError(t, attachSession(client))
	assert.Nil(t, CurrentSession())
	assert.Empty(t, client.Token())

	t.Setenv(api.EnvWardenClientCert, "")
	assert.NoError(t, attachSession(client))
	assert.NotNil(t, CurrentSession(), "without the certificate, the session is used")
}

func mustBareClient(t *testing.T) *api.Client {
	t.Helper()
	t.Setenv(api.EnvWardenAddress, clientTestAddr)
	cfg := api.DefaultConfig()
	cfg.Address = clientTestAddr
	c, err := api.NewClient(cfg)
	require.NoError(t, err)
	session = nil
	t.Cleanup(func() { session = nil })
	return c
}

func TestRequireSession(t *testing.T) {
	useSessionDir(t)
	_, _ = newSessionClient(t, map[string]string{api.EnvWardenNamespace: "team-a/dev"})
	_, _, err := RequireSession()
	assert.ErrorIs(t, err, ErrNoSession)

	saveTestSession(t, "team-a", "operator", time.Hour)
	stderr := &bytes.Buffer{}
	SetErrorWriter(stderr)
	c, s, err := RequireSession()
	require.NoError(t, err)
	assert.Equal(t, "team-a", s.Namespace)
	assert.Equal(t, "wdt.session-team-a", c.Token())
	assert.Empty(t, c.Headers().Get(api.RoleHeaderName), "no role is sent")
	assert.Contains(t, stderr.String(), "using session from namespace team-a")

	saveTestSession(t, "team-a/dev", "operator", -time.Minute)
	_, _, err = RequireSession()
	assert.ErrorIs(t, err, ErrSessionExpired)
}

// The signer proves the key over each attempt as it is sent: its method, its
// path relative to the address's own (as the server behind a prefix-stripping
// load balancer sees it), the ticket, the selectors, the query and the body;
// a retry is signed afresh. A request carrying another credential is not
// signed.
func TestProofSigner_SignsEachAttemptAsSent(t *testing.T) {
	key, err := dpop.GenerateKey()
	require.NoError(t, err)
	const ticket = "wdt.bound"
	var (
		mu     sync.Mutex
		proofs []string
		errs   []error
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		defer mu.Unlock()
		values := r.Header.Values(dpop.HeaderName)
		if r.Header.Get(api.TokenHeaderName) != ticket {
			errs = append(errs, nil)
			assert.Empty(t, values, "a request without the ticket carries no proof")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_, err := dpop.Verify(values, &dpop.Want{
			JKT: key.Thumbprint(), Method: r.Method, Now: time.Now(), Body: true,
			Path: strings.TrimPrefix(r.URL.EscapedPath(), "/warden"),
			ATH:  dpop.Hash([]byte(ticket)),
			Context: &dpop.Context{
				Role:      r.Header.Get(api.RoleHeaderName),
				Namespace: r.Header.Get(api.NamespaceHeaderName),
				Query:     dpop.Hash([]byte(r.URL.RawQuery)),
				Body:      dpop.Hash(body),
			},
		})
		proofs, errs = append(proofs, values...), append(errs, err)
		if len(proofs) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	cfg := api.DefaultConfig()
	cfg.Address = srv.URL + "/warden"
	cfg.MaxRetries = 1
	cfg.MinRetryWait, cfg.MaxRetryWait = time.Millisecond, time.Millisecond
	client, err := api.NewClient(cfg)
	require.NoError(t, err)
	client.SetToken(ticket)
	client.SetRole("operator")
	client.SetNamespace("team-a")
	client.SetRequestSigner(ProofSigner(cfg.Address, key, ticket))

	req := client.NewRequest(http.MethodPut, "/v1/sys/policies/acl/team-read")
	req.Params.Set("cas", "1")
	require.NoError(t, req.SetJSONBody(map[string]any{"policy": `path "x" {}`}))
	_, err = client.RawRequestWithContext(context.Background(), req)
	require.NoError(t, err)

	mu.Lock()
	require.Len(t, proofs, 2, "the first attempt and its retry")
	assert.NoError(t, errs[0])
	assert.NoError(t, errs[1])
	assert.NotEqual(t, proofs[0], proofs[1], "the retry is signed afresh")
	mu.Unlock()

	client.SetToken("wdt.another")
	_, err = client.RawRequestWithContext(context.Background(), client.NewRequest(http.MethodGet, "/v1/sys/mounts"))
	require.NoError(t, err)
}

// A session whose key cannot be loaded fails the command, naming why, rather
// than send a ticket that is refused without its key.
func TestClient_UnreadableSessionKeyFails(t *testing.T) {
	keyring.MockInit()
	useSessionDir(t)
	s := saveTestSession(t, "", "operator", time.Hour)
	s.KeyStore = KeyStoreOS
	require.NoError(t, SaveSession(s))
	for _, k := range []string{api.EnvWardenToken, api.EnvWardenRole, api.EnvWardenNamespace, EnvSessionKeystore} {
		t.Setenv(k, "")
	}
	t.Setenv(api.EnvWardenAddress, clientTestAddr)
	SetTestClient(nil)
	t.Cleanup(func() { SetTestClient(nil) })

	_, err := Client()
	assert.ErrorContains(t, err, "could not be read from the OS keystore")
	_, _, err = RequireSession()
	assert.ErrorContains(t, err, "could not be read from the OS keystore")

	key, err := dpop.GenerateKey()
	require.NoError(t, err)
	require.NoError(t, StoreSessionKey(s, key, io.Discard))
	require.Equal(t, KeyStoreOS, s.KeyStore)
	client, err := Client()
	require.NoError(t, err, "with the key in the keystore, the session is used")
	assert.Equal(t, s.Token, client.Token())
}

func TestProofRefusal(t *testing.T) {
	refusal := func(challenge, date string) error {
		h := http.Header{}
		h.Set("WWW-Authenticate", challenge)
		if date != "" {
			h.Set("Date", date)
		}
		return &api.ResponseError{StatusCode: http.StatusUnauthorized, Header: h}
	}
	now := time.Now().UTC()
	t.Setenv(api.EnvWardenToken, "")

	assert.Contains(t, ProofRefusal(refusal(`DPoP error="invalid_token", algs="ES256"`, "")), "refused as a bearer token")
	assert.Contains(t, ProofRefusal(refusal(`DPoP error="invalid_dpop_proof", algs="ES256"`, now.Format(http.TimeFormat))), "warden login -force")
	assert.Contains(t, ProofRefusal(refusal(`DPoP error="invalid_dpop_proof", algs="ES256"`, now.Add(-time.Minute).Format(http.TimeFormat))), "clock")
	assert.Empty(t, ProofRefusal(refusal(`Bearer error="invalid_token"`, "")))
	assert.Empty(t, ProofRefusal(errors.New("other")))

	_, skewed := ProofClockSkew(refusal(`DPoP error="invalid_dpop_proof"`, now.Add(10*time.Second).Format(http.TimeFormat)))
	assert.False(t, skewed, "within the window")

	// A bound ticket in WARDEN_TOKEN rides X-Warden-Token with no proof.
	t.Setenv(api.EnvWardenToken, "wdt.bound")
	assert.Contains(t, ProofRefusal(refusal(`DPoP error="invalid_dpop_proof", algs="ES256"`, now.Format(http.TimeFormat))), "unset WARDEN_TOKEN")
}
