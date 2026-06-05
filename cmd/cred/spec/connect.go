package spec

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"time"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	connectPort      int
	connectTimeout   time.Duration
	connectNoBrowser bool
	connectForce     bool

	ConnectCmd = &cobra.Command{
		Use:   "connect <name>",
		Short: "Complete the interactive OAuth2 consent for a credential spec",
		Long: `
Usage: warden cred spec connect <name> [flags]

  Complete the one-time human consent for an OAuth2 authorization_code spec.
  The command runs a loopback listener, opens the provider's consent page in a
  browser, captures the authorization code on the loopback redirect, and hands
  it to the server, which exchanges it (using the client secret it holds) and
  seals the resulting refresh token into the spec. The client secret never
  touches this machine.

      $ warden cred spec connect gh-oauth

  By default the listener binds an ephemeral 127.0.0.1 port. When the spec pins
  a redirect_uri (required by providers that do exact callback matching), the
  command binds that fixed port instead. Re-running replaces an existing
  authorization and requires -force.
`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.ExactArgs(1),
		RunE:          runConnect,
	}
)

func init() {
	ConnectCmd.Flags().IntVar(&connectPort, "port", 0, "Loopback port to listen on (0 = ephemeral; must match the spec's pinned redirect_uri port when set)")
	ConnectCmd.Flags().DurationVar(&connectTimeout, "timeout", 3*time.Minute, "How long to wait for the browser consent callback")
	ConnectCmd.Flags().BoolVar(&connectNoBrowser, "no-browser", false, "Print the authorize URL instead of opening a browser")
	ConnectCmd.Flags().BoolVar(&connectForce, "force", false, "Replace an existing authorization without confirmation")
}

func runConnect(cmd *cobra.Command, args []string) error {
	name := args[0]
	if err := helpers.ValidatePath(name); err != nil {
		return err
	}

	c, err := helpers.Client()
	if err != nil {
		return err
	}

	sp, err := c.Sys().GetCredentialSpec(name)
	if err != nil {
		return fmt.Errorf("error reading credential spec %s: %w", name, err)
	}
	if sp.Config["auth_method"] != "authorization_code" {
		return fmt.Errorf("credential spec %q does not use the authorization_code flow; connect is not applicable", name)
	}

	if sp.Connected && !connectForce {
		return fmt.Errorf("credential spec %q is already connected; re-run with -force to replace the existing authorization", name)
	}

	// Resolve the loopback host/port and redirect_uri. A pinned redirect_uri
	// fixes both; otherwise we bind 127.0.0.1 on -port (0 = OS-assigned).
	bindHost := "127.0.0.1"
	listenPort := connectPort
	redirectURI := ""
	if pinned := sp.Config["redirect_uri"]; pinned != "" {
		ph, pp, err := parsePinnedLoopback(pinned)
		if err != nil {
			return fmt.Errorf("spec's pinned redirect_uri is unusable: %w", err)
		}
		if cmd.Flags().Changed("port") && connectPort != pp {
			return fmt.Errorf("-port=%d conflicts with the spec's pinned redirect_uri port %d", connectPort, pp)
		}
		bindHost = ph
		listenPort = pp
		redirectURI = pinned
	}

	// Bind the listener BEFORE opening the browser, so we never send the user to
	// a consent page that redirects to a dead port. Bind the same loopback host
	// the provider will redirect to.
	ln, err := net.Listen("tcp", net.JoinHostPort(bindHost, strconv.Itoa(listenPort)))
	if err != nil {
		if redirectURI != "" {
			return fmt.Errorf("cannot bind the pinned loopback port %d: %w (free it or re-register the app's callback on another port)", listenPort, err)
		}
		return fmt.Errorf("cannot bind a loopback port: %w", err)
	}
	defer ln.Close()
	boundPort := ln.Addr().(*net.TCPAddr).Port
	if redirectURI == "" {
		redirectURI = fmt.Sprintf("http://127.0.0.1:%d/callback", boundPort)
	}

	state, err := randomURLSafe(32)
	if err != nil {
		return err
	}
	verifier, err := randomURLSafe(32)
	if err != nil {
		return err
	}
	challenge := pkceChallenge(verifier)

	authzOut, err := c.Sys().AuthorizeCredentialSpec(name, &api.AuthorizeCredentialSpecInput{
		RedirectURI:   redirectURI,
		State:         state,
		CodeChallenge: challenge,
	})
	if err != nil {
		return fmt.Errorf("error building authorize URL: %w", err)
	}

	if connectNoBrowser {
		fmt.Fprintf(os.Stderr, "Open this URL to authorize:\n\n  %s\n\n", authzOut.AuthorizeURL)
	} else {
		fmt.Fprintf(os.Stderr, "Opening browser for authorization. If it does not open, visit:\n\n  %s\n\n", authzOut.AuthorizeURL)
		if err := openBrowser(authzOut.AuthorizeURL); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not open a browser automatically (%v); open the URL above manually\n", err)
		}
	}

	code, err := awaitCallback(cmd.Context(), ln, state, connectTimeout)
	if err != nil {
		return err
	}

	connectOut, err := c.Sys().ConnectCredentialSpec(name, &api.ConnectCredentialSpecInput{
		Code:         code,
		RedirectURI:  redirectURI,
		CodeVerifier: verifier,
	})
	if err != nil {
		return fmt.Errorf("error completing connect: %w", err)
	}

	data := map[string]any{
		"name":        connectOut.Name,
		"connected":   connectOut.Connected,
		"reconnected": connectOut.Reconnected,
	}
	return helpers.RenderMap(data, func() {
		if connectOut.Reconnected {
			fmt.Printf("Success! Re-connected credential spec %s (replaced the existing authorization)\n", connectOut.Name)
		} else {
			fmt.Printf("Success! Connected credential spec %s\n", connectOut.Name)
		}
	})
}

// awaitCallback serves a single request on the loopback listener, validates the
// state, and returns the authorization code. It always shuts the server down.
func awaitCallback(parent context.Context, ln net.Listener, state string, timeout time.Duration) (string, error) {
	type result struct {
		code string
		err  error
	}
	resultCh := make(chan result, 1)

	// send delivers the first result and drops later ones: a browser may issue
	// extra requests against this listener (e.g. a /favicon.ico probe), and a
	// blocking send on the cap-1 channel would otherwise leak the goroutine.
	send := func(res result) {
		select {
		case resultCh <- res:
		default:
		}
	}

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			q := r.URL.Query()
			gotErr := q.Get("error")
			gotCode := q.Get("code")
			gotState := q.Get("state")
			if gotErr == "" && gotCode == "" && gotState == "" {
				// Not the OAuth redirect (e.g. a browser favicon probe); ignore.
				http.NotFound(w, r)
				return
			}
			if gotErr != "" {
				detail := gotErr
				if d := q.Get("error_description"); d != "" {
					detail = gotErr + ": " + d
				}
				writeCallbackPage(w, false, detail)
				send(result{err: fmt.Errorf("authorization failed: %s", detail)})
				return
			}
			// Constant-time compare to avoid leaking the state via timing.
			if subtle.ConstantTimeCompare([]byte(gotState), []byte(state)) != 1 {
				writeCallbackPage(w, false, "state parameter mismatch")
				send(result{err: errors.New("state parameter mismatch — possible CSRF, aborting")})
				return
			}
			if gotCode == "" {
				writeCallbackPage(w, false, "missing authorization code")
				send(result{err: errors.New("callback carried no authorization code")})
				return
			}
			writeCallbackPage(w, true, "")
			send(result{code: gotCode})
		}),
	}

	go func() {
		// Serve returns ErrServerClosed on Shutdown; ignore it.
		_ = srv.Serve(ln)
	}()

	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	var out result
	select {
	case out = <-resultCh:
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.Canceled) {
			out = result{err: errors.New("canceled while waiting for the browser consent")}
		} else {
			out = result{err: fmt.Errorf("timed out after %s waiting for the browser consent", timeout)}
		}
	}

	shutCtx, shutCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutCancel()
	_ = srv.Shutdown(shutCtx)

	return out.code, out.err
}

// parsePinnedLoopback returns the loopback host and port of a pinned
// redirect_uri. The host must be a loopback literal (so the listener can bind
// the same address the provider redirects to) and the port must be an explicit,
// in-range value (a fixed port is the whole point of pinning).
func parsePinnedLoopback(rawURL string) (string, int, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", 0, fmt.Errorf("invalid redirect_uri %q: %w", rawURL, err)
	}
	host := u.Hostname()
	switch host {
	case "127.0.0.1", "::1":
	default:
		return "", 0, fmt.Errorf("redirect_uri %q must be a 127.0.0.1 or ::1 loopback address", rawURL)
	}
	p := u.Port()
	if p == "" {
		return "", 0, fmt.Errorf("redirect_uri %q must include an explicit port", rawURL)
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		return "", 0, fmt.Errorf("invalid port in redirect_uri %q: %w", rawURL, err)
	}
	if n < 1 || n > 65535 {
		return "", 0, fmt.Errorf("redirect_uri %q has an out-of-range port %d", rawURL, n)
	}
	return host, n, nil
}

func randomURLSafe(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating random value: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func openBrowser(target string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", target).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", target).Start()
	default:
		return exec.Command("xdg-open", target).Start()
	}
}

func writeCallbackPage(w http.ResponseWriter, ok bool, detail string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if ok {
		fmt.Fprint(w, `<!doctype html><html><head><meta charset="utf-8"><title>Authorization complete</title></head>`+
			`<body style="font-family:sans-serif;max-width:30rem;margin:4rem auto;text-align:center">`+
			`<h2>Authorization complete</h2><p>You can close this window and return to the terminal.</p></body></html>`)
		return
	}
	w.WriteHeader(http.StatusBadRequest)
	fmt.Fprintf(w, `<!doctype html><html><head><meta charset="utf-8"><title>Authorization failed</title></head>`+
		`<body style="font-family:sans-serif;max-width:30rem;margin:4rem auto;text-align:center">`+
		`<h2>Authorization failed</h2><p>%s</p><p>Return to the terminal for details.</p></body></html>`, html.EscapeString(detail))
}
