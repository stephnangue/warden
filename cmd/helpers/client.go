package helpers

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/stephnangue/warden/api"
)

var (
	c *api.Client

	// session is the session Client attached, if any.
	session *Session
)

// SetTestClient installs an api.Client that Client() returns instead of
// constructing one from the environment. Pass nil to clear. Intended for tests.
func SetTestClient(client *api.Client) { c = client; session = nil }

// Client returns the HTTP API client of this command: built from the
// environment (the global -namespace and -role flags set it) and, when
// WARDEN_TOKEN is unset, carrying the session warden login saved for the
// Warden address and namespace (FindSession). Precedence, for the credential,
// the role and the namespace, is flag > environment > session: the session's
// role is sent only with the session's ticket, never with a WARDEN_TOKEN.
func Client() (*api.Client, error) {
	// Read the test client if present
	if c != nil {
		return c, nil
	}

	client, err := NewClientWithoutSession()
	if err != nil {
		return nil, err
	}
	if err := attachSession(client); err != nil {
		return nil, err
	}

	c = client

	return client, nil
}

// NewClientWithoutSession builds a client from the environment alone, as
// warden login does before it has a session.
func NewClientWithoutSession() (*api.Client, error) {
	config := api.DefaultConfig()

	if err := config.ReadEnvironment(); err != nil {
		return nil, fmt.Errorf("failed to read environment: %w", err)
	}

	// Build the client
	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	// Turn off retries on the CLI
	if api.ReadWardenVariable(api.EnvWardenMaxRetries) == "" {
		client.SetMaxRetries(0)
	}

	// If WARDEN_TOKEN is a JWT, send it as `Authorization: Bearer` and
	// strip X-Warden-Token. The server's transparent-auth gate fires only
	// when X-Warden-Token is empty (a JWT is not a Warden session token
	// and would fail token-store lookup); routing the credential through
	// the Authorization header lets implicit auth resolve it against the
	// namespace's auto_auth_path. The "eyJ" prefix is the base64 of `{"`,
	// the start of every JWT header — the same heuristic used server-side
	// by provider/aws to detect JWT-shaped tokens.
	if token := client.Token(); strings.HasPrefix(token, "eyJ") {
		h := client.Headers()
		h.Set("Authorization", "Bearer "+token)
		client.SetHeaders(h)
		client.ClearToken()
	}

	return client, nil
}

// attachSession sets client's credential and role from the session for its
// address and namespace, unless a credential is configured explicitly
// (WARDEN_TOKEN, or a client certificate in WARDEN_CLIENT_CERT). A session of
// an ancestor namespace is used when the namespace has none, and said so on
// stderr. An expired session is not sent: the command runs without it, after
// a notice, so commands that need no credential still work. A session store
// that cannot be used (no home directory, an unreadable or tampered file) is
// warned about and skipped, never a reason to fail a command that does not
// need it.
func attachSession(client *api.Client) error {
	if api.ReadWardenVariable(api.EnvWardenToken) != "" || api.ReadWardenVariable(api.EnvWardenClientCert) != "" {
		return nil
	}
	if _, err := SessionDir(); err != nil {
		return nil
	}
	addr, err := NormalizeAddr(client.Address())
	if err != nil {
		return nil
	}
	ns := NormalizeNamespace(client.Namespace())
	s, err := FindSession(addr, ns)
	if err != nil {
		fmt.Fprintf(errWriter, "Warning: session not used: %v\n", err)
		return nil
	}
	if s == nil {
		return nil
	}
	if err := checkSessionHeaders(s); err != nil {
		fmt.Fprintf(errWriter, "Warning: session not used: %v\n", err)
		return nil
	}
	if s.Expired(time.Now()) {
		fmt.Fprintf(errWriter, "Warning: %v\n", ErrSessionExpired)
		return nil
	}
	noteFallback(s, ns)
	client.SetToken(s.Token)
	if api.ReadWardenVariable(api.EnvWardenRole) == "" && s.Role != "" {
		client.SetRole(s.Role)
	}
	session = s
	return nil
}

// RequireSession returns a client carrying the session of its address and
// namespace (or the nearest ancestor's), and the session, for the commands
// that act on the session itself (warden role use, warden print token). It
// fails when there is none, it has expired, or the store cannot be read. The
// client sends no role and no other credential.
func RequireSession() (*api.Client, *Session, error) {
	client, err := NewClientWithoutSession()
	if err != nil {
		return nil, nil, err
	}
	ClearCredentials(client)
	addr, err := NormalizeAddr(client.Address())
	if err != nil {
		return nil, nil, err
	}
	ns := NormalizeNamespace(client.Namespace())
	s, err := FindSession(addr, ns)
	switch {
	case err != nil:
		return nil, nil, err
	case s == nil:
		return nil, nil, ErrNoSession
	case s.Expired(time.Now()):
		return nil, nil, ErrSessionExpired
	}
	if err := checkSessionHeaders(s); err != nil {
		return nil, nil, err
	}
	noteFallback(s, ns)
	client.SetToken(s.Token)
	return client, s, nil
}

// ErrNoSession: no session for the address and namespace, nor an ancestor.
var ErrNoSession = errors.New("no session for this Warden address and namespace; run warden login")

// ClearCredentials removes every credential and the role from client: the
// token, and the Authorization header a JWT in WARDEN_TOKEN is moved to.
func ClearCredentials(client *api.Client) {
	client.ClearToken()
	client.ClearRole()
	h := client.Headers()
	h.Del("Authorization")
	client.SetHeaders(h)
}

// noteFallback says on stderr when the session in use is an ancestor
// namespace's.
func noteFallback(s *Session, ns string) {
	if s.Namespace != ns {
		fmt.Fprintf(errWriter, "using session from namespace %s\n", DisplayNamespace(s.Namespace))
	}
}

// checkSessionHeaders refuses a session whose token or role cannot be sent as
// a header (a hand-edited file).
func checkSessionHeaders(s *Session) error {
	if err := ValidateHeaderValue("session token", s.Token); err != nil {
		return err
	}
	return ValidateHeaderValue("session role", s.Role)
}

// CurrentSession returns the session Client attached, or nil when the
// command's credential is not a session (WARDEN_TOKEN, a client certificate,
// none). Call Client first.
func CurrentSession() *Session { return session }
