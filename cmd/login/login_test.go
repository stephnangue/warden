package login

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
)

// fakeWarden answers the requests warden login makes: auth_url and callback
// of an oidc mount, and sys/introspect/roles.
type fakeWarden struct {
	t     *testing.T
	srv   *httptest.Server
	mount string
	roles []map[string]any

	mu          sync.Mutex
	redirectURI string
	binding     string
	namespace   string
	rolesSeen   http.Header
	callback    map[string]any
}

const fakeTicket = "wdt.fake-ticket"

func newFakeWarden(t *testing.T, roles ...string) *fakeWarden {
	t.Helper()
	f := &fakeWarden{t: t, mount: "oidc"}
	for _, r := range roles {
		f.roles = append(f.roles, map[string]any{"name": r, "description": "the " + r + " role"})
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeWarden) serve(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if raw, _ := io.ReadAll(r.Body); len(raw) > 0 {
		_ = json.Unmarshal(raw, &body)
	}
	reply := func(status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	base := "/v1/auth/" + f.mount + "/"
	switch r.URL.Path {
	case base + "auth_url":
		f.redirectURI, _ = body["redirect_uri"].(string)
		f.binding, _ = body["login_binding"].(string)
		f.namespace = r.Header.Get(api.NamespaceHeaderName)
		assert.Empty(f.t, r.Header.Get("X-Warden-Token"), "the login sends no credential")
		assert.Empty(f.t, r.Header.Get("Authorization"), "not even a JWT from WARDEN_TOKEN")
		assert.Empty(f.t, r.Header.Get(api.RoleHeaderName))
		reply(http.StatusOK, map[string]any{"data": map[string]any{
			"auth_url": "https://idp.example/authorize?state=st-1", "state": "st-1"}})
	case base + "callback":
		f.callback = body
		assert.Empty(f.t, r.Header.Get("Authorization"))
		if idpErr, _ := body["error"].(string); idpErr != "" {
			reply(http.StatusBadRequest, map[string]any{"errors": []string{
				"the identity provider refused the login: " + idpErr + ": " + fmt.Sprint(body["error_description"])}})
			return
		}
		proof, _ := body["login_proof"].(string)
		secret, _ := base64.RawURLEncoding.DecodeString(proof)
		sum := sha256.Sum256(secret)
		if body["state"] != "st-1" || body["code"] != "code-1" || base64.RawURLEncoding.EncodeToString(sum[:]) != f.binding {
			reply(http.StatusBadRequest, map[string]any{"errors": []string{"login refused"}})
			return
		}
		reply(http.StatusCreated, map[string]any{"data": map[string]any{
			"token_type": "ticket_token",
			"expire_at":  time.Now().Add(time.Hour).Format(time.RFC3339Nano),
			"data":       map[string]any{"token": fakeTicket},
		}})
	case "/v1/sys/introspect/roles":
		f.rolesSeen = r.Header.Clone()
		reply(http.StatusOK, map[string]any{"data": map[string]any{"roles": f.roles, "warnings": []string{}}})
	default:
		reply(http.StatusNotFound, map[string]any{"errors": []string{"no handler for " + r.URL.Path}})
	}
}

// browser returns an opener that lands on the CLI's redirect as the identity
// provider would, after a request carrying another state.
func (f *fakeWarden) browser(query string) func(string) error {
	return func(string) error {
		f.mu.Lock()
		redirect := f.redirectURI
		f.mu.Unlock()
		go func() {
			if resp, err := http.Get(redirect + "?state=wrong&code=evil"); err == nil {
				resp.Body.Close()
			}
			if resp, err := http.Get(redirect + "?" + query); err == nil {
				resp.Body.Close()
			}
		}()
		return nil
	}
}

type loginRun struct {
	stdout, stderr string
	err            error
}

// login runs warden login against f with flags set, in a fresh session
// directory unless dir is given.
func login(t *testing.T, f *fakeWarden, env map[string]string, set func()) loginRun {
	t.Helper()
	for _, k := range []string{api.EnvWardenToken, api.EnvWardenRole, api.EnvWardenNamespace} {
		t.Setenv(k, "")
	}
	t.Setenv(api.EnvWardenAddress, f.srv.URL)
	for k, v := range env {
		t.Setenv(k, v)
	}
	flagMethod, flagPath, flagNoBrowser, flagNoStore, flagTimeout, flagPort, flagForce = "oidc", "", false, false, 5*time.Second, 0, false
	openBrowser = f.browser("state=st-1&code=code-1")
	interactive := helpers.Interactive
	helpers.Interactive = func() bool { return false }
	t.Cleanup(func() { helpers.Interactive = interactive })
	if set != nil {
		set()
	}
	helpers.SetTestClient(nil)
	t.Cleanup(func() { helpers.SetTestClient(nil); helpers.ResetWriters() })
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	helpers.SetOutputWriter(stdout)
	helpers.SetErrorWriter(stderr)
	LoginCmd.SetOut(stdout)
	LoginCmd.SetErr(stderr)
	err := runLogin(LoginCmd, nil)
	return loginRun{stdout: stdout.String(), stderr: stderr.String(), err: err}
}

func useSessions(t *testing.T) {
	t.Helper()
	helpers.SetSessionDir(filepath.Join(t.TempDir(), "sessions"))
	t.Cleanup(func() { helpers.SetSessionDir("") })
}

func savedSession(t *testing.T, f *fakeWarden, ns string) *helpers.Session {
	t.Helper()
	addr, err := helpers.NormalizeAddr(f.srv.URL)
	require.NoError(t, err)
	s, err := helpers.LoadSession(addr, ns)
	require.NoError(t, err)
	return s
}

func TestLogin_Defaults(t *testing.T) {
	useSessions(t)
	f := newFakeWarden(t, "operator")
	run := login(t, f, nil, nil)
	require.NoError(t, run.err, run.stderr)

	assert.True(t, strings.HasPrefix(f.redirectURI, "http://localhost:"), f.redirectURI)
	assert.True(t, strings.HasSuffix(f.redirectURI, "/oidc/callback"))
	assert.Contains(t, run.stderr, "auth/oidc/")
	assert.Contains(t, run.stderr, `Using role "operator"`, "one role is chosen without asking")

	s := savedSession(t, f, "")
	require.NotNil(t, s)
	assert.Equal(t, fakeTicket, s.Token)
	assert.Equal(t, "operator", s.Role)
	assert.Equal(t, "auth/oidc/", s.Mount)
	assert.WithinDuration(t, time.Now().Add(time.Hour), s.ExpiresAt, time.Minute)

	assert.Equal(t, fakeTicket, f.rolesSeen.Get("X-Warden-Token"), "roles are listed with the new ticket")
	assert.Empty(t, f.rolesSeen.Get(api.RoleHeaderName), "and no role")
}

func TestLogin_PathAndNamespace(t *testing.T) {
	useSessions(t)
	f := newFakeWarden(t, "operator")
	f.mount = "oidc-prod"
	run := login(t, f, map[string]string{api.EnvWardenNamespace: "team-a"}, func() { flagPath = "oidc-prod/" })
	require.NoError(t, run.err, run.stderr)
	assert.Equal(t, "team-a", f.namespace)
	s := savedSession(t, f, "team-a")
	require.NotNil(t, s)
	assert.Equal(t, "auth/oidc-prod/", s.Mount)
}

func TestLogin_WrongPathHint(t *testing.T) {
	useSessions(t)
	f := newFakeWarden(t, "operator")
	run := login(t, f, nil, func() { flagPath = "nope" })
	require.Error(t, run.err)
	assert.Contains(t, run.err.Error(), "no oidc auth mount at auth/nope/")
	assert.Contains(t, run.err.Error(), "-path")
}

func TestLogin_OnlyOIDC(t *testing.T) {
	useSessions(t)
	f := newFakeWarden(t)
	run := login(t, f, nil, func() { flagMethod = "jwt" })
	assert.ErrorIs(t, run.err, helpers.ErrUsage)
}

func TestLogin_RoleSelection(t *testing.T) {
	t.Run("the requested role is checked and chosen", func(t *testing.T) {
		useSessions(t)
		f := newFakeWarden(t, "operator", "auditor")
		run := login(t, f, map[string]string{api.EnvWardenRole: "auditor"}, nil)
		require.NoError(t, run.err)
		assert.Equal(t, "auditor", savedSession(t, f, "").Role)
	})

	t.Run("an unknown requested role is refused; the session is kept", func(t *testing.T) {
		useSessions(t)
		f := newFakeWarden(t, "operator", "auditor")
		run := login(t, f, map[string]string{api.EnvWardenRole: "admin"}, nil)
		require.Error(t, run.err)
		assert.Contains(t, run.err.Error(), `role "admin" is not one you can assume here (you can assume: operator, auditor)`)
		s := savedSession(t, f, "")
		require.NotNil(t, s)
		assert.Empty(t, s.Role)
	})

	t.Run("no role granted: signed in, warned", func(t *testing.T) {
		useSessions(t)
		f := newFakeWarden(t)
		run := login(t, f, nil, nil)
		require.NoError(t, run.err)
		assert.Contains(t, run.stderr, "no group grants you a role in this namespace")
		s := savedSession(t, f, "")
		require.NotNil(t, s)
		assert.Empty(t, s.Role)
	})

	t.Run("several roles without a terminal: listed, none chosen", func(t *testing.T) {
		useSessions(t)
		f := newFakeWarden(t, "operator", "auditor")
		run := login(t, f, nil, nil)
		require.NoError(t, run.err)
		assert.Contains(t, run.stderr, "warden role use")
		assert.Contains(t, run.stderr, "  auditor   the auditor role", "the roles are listed on stderr")
		assert.Empty(t, run.stdout)
		assert.Empty(t, savedSession(t, f, "").Role)
	})
}

func TestLogin_NoStore(t *testing.T) {
	useSessions(t)
	f := newFakeWarden(t, "operator")
	run := login(t, f, nil, func() { flagNoStore = true })
	require.NoError(t, run.err)
	assert.Equal(t, fakeTicket+"\n", run.stdout)
	assert.Nil(t, savedSession(t, f, ""))
}

func TestLogin_NoBrowserPrintsURL(t *testing.T) {
	useSessions(t)
	f := newFakeWarden(t, "operator")
	opened := false
	run := login(t, f, nil, func() {
		flagNoBrowser = true
		land := f.browser("state=st-1&code=code-1")
		// The person opens the URL themselves.
		go func() {
			for {
				f.mu.Lock()
				ready := f.redirectURI != ""
				f.mu.Unlock()
				if ready {
					_ = land("")
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
		}()
		openBrowser = func(string) error { opened = true; return nil }
	})
	require.NoError(t, run.err)
	assert.False(t, opened)
	assert.Contains(t, run.stderr, "https://idp.example/authorize?state=st-1")
}

func TestLogin_IdPErrorRelayed(t *testing.T) {
	useSessions(t)
	f := newFakeWarden(t, "operator")
	run := login(t, f, nil, func() {
		openBrowser = f.browser("state=st-1&error=access_denied&error_description=cancelled")
	})
	require.Error(t, run.err)
	assert.Contains(t, run.err.Error(), "finishing the sign-in")
	assert.Contains(t, run.err.Error(), "access_denied: cancelled")
	f.mu.Lock()
	defer f.mu.Unlock()
	assert.Equal(t, "access_denied", f.callback["error"], "the error reaches callback")
	assert.Equal(t, "cancelled", f.callback["error_description"])
	assert.Equal(t, "st-1", f.callback["state"], "with the state, for the server to check first")
}

// A JWT in WARDEN_TOKEN is not sent on the login paths.
func TestLogin_IgnoresWardenTokenJWT(t *testing.T) {
	useSessions(t)
	f := newFakeWarden(t, "operator")
	run := login(t, f, map[string]string{api.EnvWardenToken: "eyJhbGciOiJSUzI1NiJ9.e30.sig"}, nil)
	require.NoError(t, run.err, run.stderr)
	assert.Equal(t, fakeTicket, f.rolesSeen.Get("X-Warden-Token"))
	assert.Empty(t, f.rolesSeen.Get("Authorization"))
}

func TestLogin_Timeout(t *testing.T) {
	useSessions(t)
	f := newFakeWarden(t, "operator")
	run := login(t, f, nil, func() {
		flagTimeout = 200 * time.Millisecond
		openBrowser = func(string) error { return nil }
	})
	require.Error(t, run.err)
	assert.Contains(t, run.err.Error(), "timed out")
}

func TestNewBinding(t *testing.T) {
	binding, proof, err := newBinding()
	require.NoError(t, err)
	secret, err := base64.RawURLEncoding.DecodeString(proof)
	require.NoError(t, err)
	assert.Len(t, secret, 32)
	sum := sha256.Sum256(secret)
	assert.Equal(t, base64.RawURLEncoding.EncodeToString(sum[:]), binding)
	other, _, _ := newBinding()
	assert.NotEqual(t, binding, other, fmt.Sprint("a fresh secret per login"))
}

func TestLogin_CallbackPortFlag(t *testing.T) {
	useSessions(t)
	f := newFakeWarden(t, "operator")
	port := freePort(t)
	run := login(t, f, nil, func() { flagPort = port })
	require.NoError(t, run.err, run.stderr)
	assert.Equal(t, fmt.Sprintf("http://localhost:%d/oidc/callback", port), f.redirectURI)

	run = login(t, f, nil, func() { flagPort = 70000 })
	assert.ErrorIs(t, run.err, helpers.ErrUsage)
}

const existingTicket = "wdt.existing-ticket"

// preSave saves a session for f's address, as an earlier warden login did.
func preSave(t *testing.T, f *fakeWarden, ns, mount, role string, ttl time.Duration) {
	t.Helper()
	addr, err := helpers.NormalizeAddr(f.srv.URL)
	require.NoError(t, err)
	require.NoError(t, helpers.SaveSession(&helpers.Session{Addr: addr, Namespace: ns, Mount: mount,
		Token: existingTicket, Role: role, ExpiresAt: time.Now().Add(ttl)}))
}

func (f *fakeWarden) signedIn() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.redirectURI != ""
}

// A valid session of the same namespace and mount is kept: no sign-in, no
// new ticket.
func TestLogin_KeepsValidSession(t *testing.T) {
	useSessions(t)
	f := newFakeWarden(t, "operator", "auditor")
	preSave(t, f, "", "auth/oidc/", "operator", time.Hour)

	run := login(t, f, nil, nil)
	require.NoError(t, run.err)
	assert.False(t, f.signedIn(), "no sign-in")
	assert.Contains(t, run.stderr, "Already signed in to namespace root through auth/oidc/")
	assert.Contains(t, run.stderr, "-force")
	s := savedSession(t, f, "")
	assert.Equal(t, existingTicket, s.Token)
	assert.Equal(t, "operator", s.Role)
}

// -role on a kept session switches the role, checked with the session's own
// ticket.
func TestLogin_KeptSessionTakesRequestedRole(t *testing.T) {
	useSessions(t)
	f := newFakeWarden(t, "operator", "auditor")
	preSave(t, f, "", "auth/oidc/", "operator", time.Hour)

	run := login(t, f, map[string]string{api.EnvWardenRole: "auditor"}, nil)
	require.NoError(t, run.err)
	assert.False(t, f.signedIn())
	assert.Equal(t, existingTicket, f.rolesSeen.Get("X-Warden-Token"))
	assert.Equal(t, "auditor", savedSession(t, f, "").Role)
	assert.Contains(t, run.stderr, `Using role "auditor"`)

	run = login(t, f, map[string]string{api.EnvWardenRole: "admin"}, nil)
	assert.ErrorContains(t, run.err, `role "admin" is not one you can assume here`)
	assert.Equal(t, "auditor", savedSession(t, f, "").Role, "unchanged")
}

// Anything else signs in again: an expired session, one about to expire, one
// of another mount, -force, -no-store, or only an ancestor namespace's
// session.
func TestLogin_SignsInAgain(t *testing.T) {
	for name, tc := range map[string]struct {
		ns, savedNS, mount string
		ttl                time.Duration
		set                func()
	}{
		"expired":                    {"", "", "auth/oidc/", -time.Minute, nil},
		"4 minutes left":             {"", "", "auth/oidc/", 4 * time.Minute, nil},
		"another mount":              {"", "", "auth/oidc-prod/", time.Hour, nil},
		"-force":                     {"", "", "auth/oidc/", time.Hour, func() { flagForce = true }},
		"-no-store":                  {"", "", "auth/oidc/", time.Hour, func() { flagNoStore = true }},
		"only an ancestor's session": {"team-a", "", "auth/oidc/", time.Hour, nil},
	} {
		t.Run(name, func(t *testing.T) {
			useSessions(t)
			f := newFakeWarden(t, "operator")
			preSave(t, f, tc.savedNS, tc.mount, "operator", tc.ttl)
			run := login(t, f, map[string]string{api.EnvWardenNamespace: tc.ns}, tc.set)
			require.NoError(t, run.err, run.stderr)
			assert.True(t, f.signedIn(), "signed in again")
			assert.NotContains(t, run.stderr, "Already signed in")
		})
	}
}
