//go:build e2e

package helpers

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/internal/playground"
)

// HumanIdP is the playground's authorization server on a free loopback port:
// an OpenID Connect provider people sign in to without being asked anything,
// as whoever the login_hint names among People. The e2e cluster's nodes run
// on this host, so they reach it.
type HumanIdP struct {
	URL string
}

// StartHumanIdP serves an identity provider signing in people (subject to
// extra ID token claims) until the test ends.
func StartHumanIdP(t *testing.T, people map[string]map[string]any) *HumanIdP {
	t.Helper()
	var h atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.Load().(http.Handler).ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	idp, err := playground.NewIdP(srv.URL)
	require.NoError(t, err)
	as, err := playground.NewAuthServer(playground.AuthServerConfig{
		IdP: idp,
		// The token exchange is not used here; its keys are fetched lazily.
		WardenIssuer:  "https://warden.invalid",
		WardenJWKSURL: "https://warden.invalid/jwks",
		Audiences:     []string{"unused"},
		People:        people,
	})
	require.NoError(t, err)
	h.Store(as.Handler())
	return &HumanIdP{URL: srv.URL}
}

// OIDCMountConfig is the config of an oidc auth mount signing people in at
// idp, with extra merged over it: a public client (PKCE), ES256 ID tokens,
// the warden CLI's loopback redirect on any port, and the roles and groups
// claims published as facts.
func OIDCMountConfig(idp *HumanIdP, extra map[string]any) map[string]any {
	cfg := map[string]any{
		"oidc_discovery_url":    idp.URL,
		"client_id":             playground.HumanClientID,
		"client_auth":           "none",
		"supported_algs":        []string{"ES256"},
		"allowed_redirect_uris": []string{"http://localhost/oidc/callback"},
		"facts":                 map[string]any{"roles": "roles", "groups": "groups"},
		"session_ttl":           "1h",
	}
	for k, v := range extra {
		cfg[k] = v
	}
	return cfg
}

// UniqueMount returns a mount path no earlier run left behind.
func UniqueMount(prefix string) string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return prefix + "-" + hex.EncodeToString(b)
}

// LoginRun is what warden login printed and how it ended.
type LoginRun struct {
	Stdout, Stderr string
	Err            error
}

// loginDeadline bounds one warden login run: the browser leg takes a second,
// so a login still running after this is stuck, and is killed.
const loginDeadline = 90 * time.Second

// OIDCLogin runs warden login against the node at port with HOME at home (so
// sessions are the test's own), as the browser would: it reads the
// authorization URL the CLI prints (-no-browser), calls beforeBrowser if set,
// opens the URL signed in as person, and follows the identity provider's
// redirect to the CLI's listener. args are extra flags; env overlays the
// environment (WARDEN_TOKEN and WARDEN_ROLE are cleared unless env sets them).
//
// beforeBrowser runs off the test goroutine, so it reports a failure as an
// error rather than failing the test: the login is then killed and the error
// fails the test here. A login never outlives loginDeadline nor the test.
func OIDCLogin(t *testing.T, port int, home, person string, env map[string]string, beforeBrowser func() error, args ...string) LoginRun {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), loginDeadline)
	defer cancel()
	flags := []string{"login", "-no-browser", "-callback-port=0", "-timeout=" + loginDeadline.String()}
	cmd := exec.CommandContext(ctx, WardenBin(), append(flags, args...)...)
	cmd.WaitDelay = 5 * time.Second
	cmd.Env = append(cmd.Environ(), "WARDEN_SKIP_VERIFY=true", "WARDEN_ADDR="+NodeURL(port), "HOME="+home,
		"WARDEN_TOKEN=", "WARDEN_ROLE=", "WARDEN_NAMESPACE=")
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	pipe, err := cmd.StderrPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())

	var stderr bytes.Buffer
	var browser sync.WaitGroup
	var browserErr error
	scanner := bufio.NewScanner(pipe)
	for scanner.Scan() {
		line := scanner.Text()
		stderr.WriteString(line + "\n")
		u := strings.TrimSpace(line)
		if strings.HasPrefix(u, "http") && strings.Contains(u, "/authorize?") {
			browser.Add(1)
			go func() {
				defer browser.Done()
				if beforeBrowser != nil {
					if err := beforeBrowser(); err != nil {
						browserErr = err
						cancel()
						return
					}
				}
				openAsBrowser(u, person)
			}()
		}
	}
	err = cmd.Wait()
	browser.Wait()
	require.NoError(t, browserErr, "before opening the sign-in URL")
	require.NoError(t, ctx.Err(), "warden login still running after %s:\n%s", loginDeadline, stderr.String())
	return LoginRun{Stdout: stdout.String(), Stderr: stderr.String(), Err: err}
}

// FailOver makes the leader at port step down and waits for a leader, which
// it returns. It reports failures as errors, for use off the test goroutine
// (OIDCLogin's beforeBrowser).
func FailOver(port int) (int, error) {
	if out, err := runScript(filepath.Join(E2EDir(), "tools", "step_down.sh"), fmt.Sprintf("%d", port)); err != nil {
		return 0, fmt.Errorf("step_down.sh: %v\n%s", err, out)
	}
	for range 30 {
		for _, p := range NodePorts {
			if status, _ := TryRequest("GET", NodeURL(p)+"/v1/sys/health", nil, ""); status == http.StatusOK {
				return p, nil
			}
		}
		time.Sleep(time.Second)
	}
	return 0, errors.New("no leader within 30s of the step-down")
}

// openAsBrowser opens the authorization URL signed in as person; the default
// client follows the redirect to the CLI's loopback listener.
func openAsBrowser(authURL, person string) {
	if person != "" {
		authURL += "&login_hint=" + url.QueryEscape(person)
	}
	if resp, err := http.Get(authURL); err == nil {
		resp.Body.Close()
	}
}

// SessionTicket returns the ticket of the only session saved under home.
func SessionTicket(t *testing.T, home string) string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(home, ".warden", "sessions", "*.json"))
	require.NoError(t, err)
	require.Len(t, files, 1, "one session saved")
	data, err := os.ReadFile(files[0])
	require.NoError(t, err)
	var s struct {
		Token string `json:"token"`
		Role  string `json:"role"`
	}
	require.NoError(t, json.Unmarshal(data, &s))
	require.True(t, strings.HasPrefix(s.Token, "wdt."), "a ticket")
	return s.Token
}

// SessionCLI runs a warden command against the node at port with the
// session saved under home: no WARDEN_TOKEN, so the session is the
// credential.
func SessionCLI(t *testing.T, port int, home string, env map[string]string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	all := map[string]string{"HOME": home, "WARDEN_TOKEN": "", "WARDEN_ROLE": "", "WARDEN_NAMESPACE": ""}
	for k, v := range env {
		all[k] = v
	}
	return WardenCLISplitWithPort(t, port, all, args...)
}

// TicketRequest makes a request to the node at port presenting ticket on
// X-Warden-Token, with extra headers.
func TicketRequest(t *testing.T, method, path string, port int, ticket string, headers map[string]string) (int, []byte) {
	t.Helper()
	h := map[string]string{"X-Warden-Token": ticket}
	for k, v := range headers {
		h[k] = v
	}
	return DoRequest(t, method, fmt.Sprintf("%s/v1/%s", NodeURL(port), path), h, "")
}

// TicketRole is a role list_roles returns.
type TicketRole struct {
	Name     string `json:"name"`
	Provider string `json:"provider"`
	Skill    string `json:"skill"`
	URL      string `json:"url"`
}

// TicketListRoles calls list_roles on the MCP discovery server of the node at
// port, presenting ticket on X-Warden-Token.
func TicketListRoles(t *testing.T, port int, ticket string) []TicketRole {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "e2e-human", Version: "1.0.0"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint: NodeURL(port) + "/v1/sys/mcp",
		HTTPClient: &http.Client{Transport: headerTransport{
			base:   &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec // self-signed e2e cert
			header: "X-Warden-Token",
			value:  ticket,
		}},
		DisableStandaloneSSE: true,
	}, nil)
	require.NoError(t, err, "connect to /v1/sys/mcp with a ticket")
	defer session.Close()

	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "list_roles"})
	require.NoError(t, err)
	require.False(t, res.IsError, "list_roles: %v", res.Content)
	raw, err := json.Marshal(res.StructuredContent)
	require.NoError(t, err)
	var out struct {
		Roles []TicketRole `json:"roles"`
	}
	require.NoError(t, json.Unmarshal(raw, &out))
	return out.Roles
}

// headerTransport sets one header on every request.
type headerTransport struct {
	base          http.RoundTripper
	header, value string
}

func (h headerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set(h.header, h.value)
	return h.base.RoundTrip(r)
}
