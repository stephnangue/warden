package helpers

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/api"
)

const clientTestAddr = "https://warden.example:8400"

// newSessionClient builds Client() afresh under env, with sessions in a
// temporary directory, and returns it and what it wrote on stderr.
func newSessionClient(t *testing.T, env map[string]string) (*api.Client, string) {
	t.Helper()
	for _, k := range []string{api.EnvWardenToken, api.EnvWardenRole, api.EnvWardenNamespace} {
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
