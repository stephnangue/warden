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

	"github.com/zalando/go-keyring"

	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
	"github.com/stephnangue/warden/helper/dpop"
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

	// refused is a ticket sys/introspect/roles answers refusedStatus to:
	// one whose mount was disabled, or a server failing.
	refused       string
	refusedStatus int

	// bind makes the mount bind its ticket to the key the login offers
	// (jkt), and check the proof of it at callback and on
	// sys/introspect/roles, as the server does; proofs counts those that
	// passed. skew, when set, is how far the server's clock is ahead.
	bind   bool
	jkt    string
	proofs int
	skew   time.Duration

	// onRoles runs on every sys/introspect/roles, as the role picker lists
	// the roles.
	onRoles func()
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
	raw, _ := io.ReadAll(r.Body)
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &body)
	}
	reply := func(status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now().Add(f.skew)
	w.Header().Set("Date", now.UTC().Format(http.TimeFormat))
	// checkProof checks r's proof of f.jkt, as the server does; a request
	// proof (ticket set) signs the request too.
	checkProof := func(ticket string) bool {
		want := &dpop.Want{JKT: f.jkt, Method: r.Method, Path: r.URL.EscapedPath(), Now: now}
		if ticket != "" {
			want.ATH, want.Body = dpop.Hash([]byte(ticket)), true
			want.Context = &dpop.Context{
				Role:        r.Header.Get(api.RoleHeaderName),
				Namespace:   r.Header.Get(api.NamespaceHeaderName),
				Provider:    r.Header.Get(api.ProviderHeaderName),
				Request:     r.Header.Get("X-Warden-Request"),
				ContentType: r.Header.Get("Content-Type"),
				Query:       dpop.Hash([]byte(r.URL.RawQuery)),
				Body:        dpop.Hash(raw),
			}
		}
		if _, err := dpop.Verify(r.Header.Values(dpop.HeaderName), want); err != nil {
			w.Header().Set("WWW-Authenticate", `DPoP error="invalid_dpop_proof", algs="ES256"`)
			reply(http.StatusUnauthorized, map[string]any{"errors": []string{err.Error()}})
			return false
		}
		f.proofs++
		return true
	}
	base := "/v1/auth/" + f.mount + "/"
	switch r.URL.Path {
	case base + "auth_url":
		f.redirectURI, _ = body["redirect_uri"].(string)
		f.binding, _ = body["login_binding"].(string)
		f.jkt, _ = body["dpop_jkt"].(string)
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
		data := map[string]any{
			"token_type": "ticket_token",
			"expire_at":  time.Now().Add(time.Hour).Format(time.RFC3339Nano),
			"data":       map[string]any{"token": fakeTicket},
		}
		if f.bind && f.jkt != "" {
			if !checkProof("") {
				return
			}
			data["dpop_bound"] = "true"
		}
		reply(http.StatusCreated, map[string]any{"data": data})
	case "/v1/sys/introspect/roles":
		f.rolesSeen = r.Header.Clone()
		if f.onRoles != nil {
			f.onRoles()
		}
		if f.refused != "" && r.Header.Get("X-Warden-Token") == f.refused {
			reply(f.refusedStatus, map[string]any{"errors": []string{"the presented ticket is not valid here"}})
			return
		}
		if f.bind && r.Header.Get("X-Warden-Token") == fakeTicket && !checkProof(fakeTicket) {
			return
		}
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
	for _, k := range []string{api.EnvWardenToken, api.EnvWardenRole, api.EnvWardenNamespace, helpers.EnvSessionKeystore} {
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

// A saved session the server no longer accepts (its mount disabled, its
// namespace deleted) is not kept: warden login signs in again.
func TestLogin_RefusedSessionSignsInAgain(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		useSessions(t)
		f := newFakeWarden(t, "operator")
		f.refused, f.refusedStatus = existingTicket, status
		preSave(t, f, "", "auth/oidc/", "operator", time.Hour)

		run := login(t, f, nil, nil)
		require.NoError(t, run.err, run.stderr)
		assert.Contains(t, run.stderr, "no longer accepted; signing in again", "status %d", status)
		assert.True(t, f.signedIn())
		assert.Equal(t, fakeTicket, savedSession(t, f, "").Token)
	}
}

// The check sends the saved ticket, and no role.
func TestLogin_KeptSessionIsChecked(t *testing.T) {
	useSessions(t)
	f := newFakeWarden(t, "operator")
	preSave(t, f, "", "auth/oidc/", "operator", time.Hour)
	run := login(t, f, nil, nil)
	require.NoError(t, run.err)
	assert.False(t, f.signedIn())
	assert.Equal(t, existingTicket, f.rolesSeen.Get("X-Warden-Token"))
	assert.Empty(t, f.rolesSeen.Get(api.RoleHeaderName))
}

// A server that cannot answer is an error, not a reason to sign in.
func TestLogin_SessionCheckFails(t *testing.T) {
	useSessions(t)
	f := newFakeWarden(t, "operator")
	f.refused, f.refusedStatus = existingTicket, http.StatusInternalServerError
	preSave(t, f, "", "auth/oidc/", "operator", time.Hour)
	run := login(t, f, nil, nil)
	assert.ErrorContains(t, run.err, "checking the saved session")
	assert.False(t, f.signedIn())
}

// sessionKeyItem is the keystore item of the session for f's address.
func sessionKeyItem(t *testing.T, f *fakeWarden) string {
	t.Helper()
	addr, err := helpers.NormalizeAddr(f.srv.URL)
	require.NoError(t, err)
	sum := sha256.Sum256([]byte(addr + "|"))
	return "session-" + fmt.Sprintf("%x", sum)[:16]
}

// A mount that binds tickets gets the thumbprint of a new key, a proof of it
// at callback, and a proof on every request after; the key is kept in the OS
// keystore, never in the session file.
func TestLogin_BindsKey(t *testing.T) {
	keyring.MockInit()
	useSessions(t)
	f := newFakeWarden(t, "operator")
	f.bind = true
	run := login(t, f, nil, nil)
	require.NoError(t, run.err, run.stderr)

	s := savedSession(t, f, "")
	assert.Equal(t, helpers.KeyStoreOS, s.KeyStore)
	assert.Empty(t, s.Key, "the key is not in the file")
	enc, err := keyring.Get("warden", sessionKeyItem(t, f))
	require.NoError(t, err)
	raw, err := base64.RawURLEncoding.DecodeString(enc)
	require.NoError(t, err)
	key, err := dpop.ParseKey(raw)
	require.NoError(t, err)
	assert.Equal(t, f.jkt, key.Thumbprint(), "the key offered is the key kept")
	assert.Equal(t, 2, f.proofs, "the callback's proof and the role listing's")
	assert.NotContains(t, run.stderr, "Warning")

	// The next login keeps the session, checking it with a proof.
	run = login(t, f, nil, nil)
	require.NoError(t, run.err, run.stderr)
	assert.Contains(t, run.stderr, "Already signed in")
	assert.Equal(t, 3, f.proofs)

	// Logout removes the key with the session.
	setSessionEnv(t, "")
	t.Setenv(api.EnvWardenAddress, f.srv.URL)
	require.NoError(t, LogoutCmd.RunE(LogoutCmd, nil))
	_, err = keyring.Get("warden", sessionKeyItem(t, f))
	assert.ErrorIs(t, err, keyring.ErrNotFound)
}

// A keystore that cannot be written puts the key in the session file, and
// says so; WARDEN_SESSION_KEYSTORE=file does the same without a word.
func TestLogin_KeyInSessionFile(t *testing.T) {
	for name, tc := range map[string]struct {
		env      map[string]string
		mock     func()
		warnings bool
	}{
		"keystore unavailable": {nil, func() { keyring.MockInitWithError(fmt.Errorf("no secret service")) }, true},
		"chosen":               {map[string]string{helpers.EnvSessionKeystore: "file"}, keyring.MockInit, false},
	} {
		t.Run(name, func(t *testing.T) {
			tc.mock()
			useSessions(t)
			f := newFakeWarden(t, "operator")
			f.bind = true
			run := login(t, f, tc.env, nil)
			require.NoError(t, run.err, run.stderr)

			s := savedSession(t, f, "")
			assert.Equal(t, helpers.KeyStoreFile, s.KeyStore)
			assert.NotEmpty(t, s.Key)
			assert.Equal(t, tc.warnings, strings.Contains(run.stderr, "kept in the session file"), run.stderr)
			assert.Equal(t, 2, f.proofs)
		})
	}
}

// A server that does not bind tickets ignores the key offered; -no-store,
// for a token handed to another tool, offers none.
func TestLogin_BearerTicket(t *testing.T) {
	keyring.MockInit()
	useSessions(t)
	f := newFakeWarden(t, "operator")
	run := login(t, f, nil, nil)
	require.NoError(t, run.err, run.stderr)
	assert.NotEmpty(t, f.jkt, "a key is offered")
	s := savedSession(t, f, "")
	assert.Empty(t, s.KeyStore, "the server did not bind the ticket")
	assert.False(t, s.Bound())
	_, err := keyring.Get("warden", sessionKeyItem(t, f))
	assert.ErrorIs(t, err, keyring.ErrNotFound)

	run = login(t, f, nil, func() { flagNoStore = true })
	require.NoError(t, run.err, run.stderr)
	assert.Empty(t, f.jkt, "-no-store offers no key")
}

// A new login writes its key to the keystore only once its role is chosen,
// just before its file: a login stopped in the role picker leaves the previous
// session and its key as they were. A new session kept in the file removes the
// previous session's keystore item.
func TestLogin_KeystoreChangesWithTheFile(t *testing.T) {
	keyring.MockInit()
	useSessions(t)
	f := newFakeWarden(t, "operator")
	f.bind = true
	require.NoError(t, login(t, f, nil, nil).err)
	first, err := keyring.Get("warden", sessionKeyItem(t, f))
	require.NoError(t, err)

	var during string
	f.onRoles = func() { during, _ = keyring.Get("warden", sessionKeyItem(t, f)) }
	run := login(t, f, nil, func() { flagForce = true })
	require.NoError(t, run.err, run.stderr)
	assert.Equal(t, first, during, "the previous key stays while the role is chosen")
	second, err := keyring.Get("warden", sessionKeyItem(t, f))
	require.NoError(t, err)
	assert.NotEqual(t, first, second, "then the new key replaces it")

	f.onRoles = nil
	run = login(t, f, map[string]string{helpers.EnvSessionKeystore: "file"}, func() { flagForce = true })
	require.NoError(t, run.err, run.stderr)
	assert.Equal(t, helpers.KeyStoreFile, savedSession(t, f, "").KeyStore)
	_, err = keyring.Get("warden", sessionKeyItem(t, f))
	assert.ErrorIs(t, err, keyring.ErrNotFound, "the previous session's item is removed")
}

// Logout removes the session file even when the keystore cannot be reached,
// and only warns about the key: the file holds the ticket.
func TestLogout_KeystoreUnreachable(t *testing.T) {
	keyring.MockInit()
	useSessions(t)
	f := newFakeWarden(t, "operator")
	f.bind = true
	require.NoError(t, login(t, f, nil, nil).err)

	keyring.MockInitWithError(fmt.Errorf("no session bus"))
	setSessionEnv(t, "")
	t.Setenv(api.EnvWardenAddress, f.srv.URL)
	stderr := &bytes.Buffer{}
	LogoutCmd.SetErr(stderr)
	require.NoError(t, LogoutCmd.RunE(LogoutCmd, nil))
	assert.Nil(t, savedSession(t, f, ""), "the file is gone")
	assert.Contains(t, stderr.String(), "Warning")
	assert.Contains(t, stderr.String(), "no session bus")
}

// A saved session whose key cannot be read is not used: warden login says
// why and signs in again, with a new key.
func TestLogin_UnreadableKeySignsInAgain(t *testing.T) {
	keyring.MockInit()
	useSessions(t)
	f := newFakeWarden(t, "operator")
	f.bind = true
	require.NoError(t, login(t, f, nil, nil).err)
	require.NoError(t, keyring.Delete("warden", sessionKeyItem(t, f)))

	run := login(t, f, nil, nil)
	require.NoError(t, run.err, run.stderr)
	assert.Contains(t, run.stderr, "cannot be used")
	assert.Contains(t, run.stderr, "OS keystore")
	_, err := keyring.Get("warden", sessionKeyItem(t, f))
	assert.NoError(t, err, "the new login keeps a new key")
}

// A proof refused because this machine's clock is off the server's is not a
// reason to sign in again, which would not help: warden login says so.
func TestLogin_ClockSkew(t *testing.T) {
	keyring.MockInit()
	useSessions(t)
	f := newFakeWarden(t, "operator")
	f.bind = true
	require.NoError(t, login(t, f, nil, nil).err)

	f.mu.Lock()
	f.skew, f.redirectURI = 2*time.Minute, ""
	f.mu.Unlock()
	run := login(t, f, nil, nil)
	require.Error(t, run.err)
	assert.False(t, f.signedIn(), "no sign-in")
	assert.Equal(t, helpers.ExitAuth, helpers.RenderError(run.err))
	assert.Contains(t, helpers.ProofRefusal(run.err), "off the server's")
	// The server's Date has whole seconds.
	skew, skewed := helpers.ProofClockSkew(run.err)
	assert.True(t, skewed)
	assert.InDelta(t, (-2 * time.Minute).Seconds(), skew.Seconds(), 1.5)
}
