package spec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePinnedLoopback(t *testing.T) {
	h, p, err := parsePinnedLoopback("http://127.0.0.1:8765/callback")
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1", h)
	assert.Equal(t, 8765, p)

	h, p, err = parsePinnedLoopback("http://[::1]:9000/cb")
	require.NoError(t, err)
	assert.Equal(t, "::1", h)
	assert.Equal(t, 9000, p)

	_, _, err = parsePinnedLoopback("http://127.0.0.1/callback") // no port
	assert.Error(t, err)

	_, _, err = parsePinnedLoopback("://bad")
	assert.Error(t, err)

	_, _, err = parsePinnedLoopback("http://127.0.0.1:0/callback") // port 0
	assert.Error(t, err)

	// A non-loopback host is rejected so the auth code can't be directed off-machine.
	_, _, err = parsePinnedLoopback("https://app.example.com:8080/cb")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "loopback")
}

func TestPKCEChallenge(t *testing.T) {
	// RFC 7636 Appendix B test vector.
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	assert.Equal(t, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", pkceChallenge(verifier))
}

func TestRandomURLSafe_DistinctAndDecodable(t *testing.T) {
	a, err := randomURLSafe(32)
	require.NoError(t, err)
	b, err := randomURLSafe(32)
	require.NoError(t, err)
	assert.NotEqual(t, a, b)
	assert.NotEmpty(t, a)
}

// fireCallback issues the loopback redirect the browser would, once the
// listener is accepting. The listener is already bound, so the connection sits
// in the backlog until awaitCallback's server starts serving.
func fireCallback(t *testing.T, port int, query string) {
	t.Helper()
	go func() {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/callback?%s", port, query))
		if err == nil {
			resp.Body.Close()
		}
	}()
}

func TestAwaitCallback_Success(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port

	fireCallback(t, port, "code=the-code&state=the-state")
	code, err := awaitCallback(context.Background(), ln, "the-state", 5*time.Second)
	require.NoError(t, err)
	assert.Equal(t, "the-code", code)
}

func TestAwaitCallback_StateMismatch(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port

	fireCallback(t, port, "code=the-code&state=attacker-state")
	_, err = awaitCallback(context.Background(), ln, "the-state", 5*time.Second)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "state parameter mismatch")
}

func TestAwaitCallback_ProviderError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port

	fireCallback(t, port, "error=access_denied&error_description=user+declined")
	_, err = awaitCallback(context.Background(), ln, "the-state", 5*time.Second)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "access_denied")
}

// A callback that arrives with a valid state but an empty code must fail fast
// with a clear error, not hang until the timeout.
func TestAwaitCallback_EmptyCode(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port

	fireCallback(t, port, "state=the-state&code=")
	_, err = awaitCallback(context.Background(), ln, "the-state", 5*time.Second)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no authorization code")
}

func TestAwaitCallback_Timeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	_, err = awaitCallback(context.Background(), ln, "the-state", 150*time.Millisecond)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timed out")
}

func TestAwaitCallback_ContextCanceled(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	_, err = awaitCallback(ctx, ln, "the-state", 5*time.Second)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "canceled")
}

// A non-callback request (e.g. a browser favicon probe) must be ignored, not
// mistaken for a failed callback that aborts the flow.
func TestAwaitCallback_IgnoresNonCallbackRequest(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port

	go func() {
		// Favicon probe with no query params — must be ignored.
		if r, e := http.Get(fmt.Sprintf("http://127.0.0.1:%d/favicon.ico", port)); e == nil {
			r.Body.Close()
		}
		// The genuine callback follows.
		if r, e := http.Get(fmt.Sprintf("http://127.0.0.1:%d/callback?code=real&state=the-state", port)); e == nil {
			r.Body.Close()
		}
	}()

	code, err := awaitCallback(context.Background(), ln, "the-state", 5*time.Second)
	require.NoError(t, err)
	assert.Equal(t, "real", code)
}

// setupConnectTest installs a test API client whose spec-read returns the given
// config and connected flag, and resets package state afterward.
func setupConnectTest(t *testing.T, specConfig map[string]string, connected bool) (*bytes.Buffer, *bytes.Buffer) {
	t.Helper()

	body := map[string]any{"data": map[string]any{
		"name":      "gh",
		"type":      "oauth_bearer_token",
		"source":    "gh-src",
		"config":    specConfig,
		"connected": connected,
	}}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(body)
	}))

	cfg := api.DefaultConfig()
	cfg.Address = server.URL
	client, err := api.NewClient(cfg)
	require.NoError(t, err)
	helpers.SetTestClient(client)

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	helpers.SetOutputWriter(stdout)
	helpers.SetErrorWriter(stderr)

	origForce, origPort := connectForce, connectPort
	origNoBrowser, origTimeout := connectNoBrowser, connectTimeout
	connectForce, connectPort = false, 0

	t.Cleanup(func() {
		server.Close()
		helpers.SetTestClient(nil)
		helpers.SetOutputFormat("")
		helpers.SetFields("")
		helpers.ResetWriters()
		connectForce, connectPort = origForce, origPort
		connectNoBrowser, connectTimeout = origNoBrowser, origTimeout
	})

	return stdout, stderr
}

func TestRunConnect_RejectsNonAuthorizationCode(t *testing.T) {
	setupConnectTest(t, map[string]string{"auth_method": "client_credentials"}, false)
	err := runConnect(ConnectCmd, []string{"gh"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not use the authorization_code flow")
}

func TestRunConnect_RejectsAlreadyConnectedWithoutForce(t *testing.T) {
	setupConnectTest(t, map[string]string{"auth_method": "authorization_code"}, true)
	err := runConnect(ConnectCmd, []string{"gh"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already connected")
}

func TestRunConnect_PortConflict(t *testing.T) {
	setupConnectTest(t, map[string]string{
		"auth_method":  "authorization_code",
		"redirect_uri": "http://127.0.0.1:8765/callback",
	}, false)

	// A command with -port explicitly set to a value that disagrees with the
	// spec's pinned port must be rejected before any browser/listener work.
	cmd := &cobra.Command{}
	cmd.Flags().IntVar(&connectPort, "port", 0, "")
	require.NoError(t, cmd.Flags().Set("port", "1234"))

	err := runConnect(cmd, []string{"gh"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "conflicts with the spec's pinned redirect_uri port 8765")
}
