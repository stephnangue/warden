// Package login implements warden login, warden logout and warden print: a
// person signs in through an oidc auth mount in the browser, and the session
// it issues is kept for the commands that follow.
package login

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
	"github.com/stephnangue/warden/cmd/roles"
)

var (
	flagMethod    string
	flagPath      string
	flagNoBrowser bool
	flagNoStore   bool
	flagTimeout   time.Duration
	flagPort      int

	LoginCmd = &cobra.Command{
		Use:           "login",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Sign in with your identity provider and choose a role",
		Long: `
Usage: warden login [options]

  Signs you in through the oidc auth mount of the current namespace: the
  browser opens at your identity provider, and once you have signed in Warden
  issues a session (valid for the mount's session_ttl). The session is kept in
  ~/.warden/sessions, one per Warden address and namespace, and used by the
  warden commands that follow.

  Then warden login lists the roles your groups grant you and lets you choose
  the one commands run under (arrows to move, type to filter, Enter to
  select). With one role it is chosen for you; with -role (or WARDEN_ROLE) it
  is checked and chosen without asking. Switch later with warden role use.

  The mount defaults to auth/oidc/; name another with -path. -namespace signs
  you in to that namespace's mount; a session of a parent namespace also
  serves its children.

  The identity provider sends the browser back to
  http://localhost:8251/oidc/callback: register that redirect URI at the
  provider. -callback-port changes the port; -callback-port=0 picks a free one,
  for a provider that accepts any loopback port.

  Examples:

      $ warden login
      $ warden login -path=oidc-prod
      $ warden login -role=operator
      $ warden login -n team-a
      $ warden login -no-browser
      $ warden login -callback-port=9000
`,
		Args: cobra.NoArgs,
		RunE: runLogin,
	}
)

func init() {
	LoginCmd.Flags().StringVar(&flagMethod, "method", "oidc", "Auth method to sign in with; oidc is the one interactive method")
	LoginCmd.Flags().StringVar(&flagPath, "path", "", "Path of the auth mount, under auth/ (default: the method's name)")
	LoginCmd.Flags().BoolVar(&flagNoBrowser, "no-browser", false, "Print the sign-in URL instead of opening a browser")
	LoginCmd.Flags().BoolVar(&flagNoStore, "no-store", false, "Print the session token on stdout instead of saving the session")
	LoginCmd.Flags().DurationVar(&flagTimeout, "timeout", 5*time.Minute, "How long to wait for the sign-in to finish in the browser")
	LoginCmd.Flags().IntVar(&flagPort, "callback-port", defaultCallbackPort,
		"Port of the sign-in redirect, http://localhost:<port>/oidc/callback; 0 picks a free one")
}

func runLogin(cmd *cobra.Command, _ []string) error {
	if flagMethod != "oidc" {
		return fmt.Errorf("-method %q: oidc is the one method warden login signs in with: %w", flagMethod, helpers.ErrUsage)
	}
	mount := strings.Trim(flagPath, "/")
	if mount == "" {
		mount = flagMethod
	}
	stderr := cmd.ErrOrStderr()

	client, err := helpers.NewClientWithoutSession()
	if err != nil {
		return err
	}
	// The login itself runs with no credential (not even a JWT that
	// WARDEN_TOKEN moved to Authorization) and no role; the role asked for
	// (-role, WARDEN_ROLE) is the one to choose afterwards.
	requested := api.ReadWardenVariable(api.EnvWardenRole)
	helpers.ClearCredentials(client)
	addr, err := helpers.NormalizeAddr(client.Address())
	if err != nil {
		return err
	}
	ns := helpers.NormalizeNamespace(client.Namespace())

	s, err := signIn(cmd.Context(), client, mount, stderr)
	if err != nil {
		return err
	}
	s.Addr, s.Namespace = addr, ns

	client.SetToken(s.Token)
	role, roleErr := roles.ChooseRole(client, requested)
	s.Role = role

	if flagNoStore {
		fmt.Fprintln(cmd.OutOrStdout(), s.Token)
	} else if err := helpers.SaveSession(s); err != nil {
		return err
	}
	fmt.Fprintf(stderr, "Signed in to namespace %s; session valid until %s (%s).\n",
		helpers.DisplayNamespace(ns), s.ExpiresAt.Local().Format("15:04"), time.Until(s.ExpiresAt).Round(time.Minute))
	if role != "" {
		fmt.Fprintf(stderr, "Using role %q for warden commands. Switch with: warden role use\n", role)
	}
	return roleErr
}

// signIn runs the login against the oidc mount at auth/<mount>/: auth_url,
// the browser, the loopback redirect, then callback. It returns the session
// with its token, mount and expiry.
func signIn(ctx context.Context, client *api.Client, mount string, stderr io.Writer) (*helpers.Session, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if flagPort < 0 || flagPort > 65535 {
		return nil, fmt.Errorf("-callback-port %d is not a port: %w", flagPort, helpers.ErrUsage)
	}
	l, err := newCallbackListener(flagPort)
	if err != nil {
		return nil, err
	}
	defer l.Close()

	binding, proof, err := newBinding()
	if err != nil {
		return nil, err
	}
	base := "auth/" + mount + "/"
	res, err := client.Operator().Write(base+"auth_url", map[string]any{
		"redirect_uri":  l.RedirectURI(),
		"login_binding": binding,
	})
	if err != nil {
		var re *api.ResponseError
		if errors.As(err, &re) && re.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("no oidc auth mount at %s in this namespace; name it with -path: %w", base, err)
		}
		return nil, fmt.Errorf("starting the sign-in: %w", err)
	}
	authURL, _ := dataString(res, "auth_url")
	state, _ := dataString(res, "state")
	if authURL == "" || state == "" {
		return nil, errors.New("starting the sign-in: the server returned no authorization URL")
	}
	l.Serve(state)

	if flagNoBrowser {
		fmt.Fprintf(stderr, "Open this URL in a browser to sign in through %s:\n\n  %s\n\n", base, authURL)
	} else {
		fmt.Fprintf(stderr, "Opening the browser to sign in through %s…\n", base)
		if err := openBrowser(authURL); err != nil {
			fmt.Fprintf(stderr, "Could not open a browser; open this URL to sign in:\n\n  %s\n\n", authURL)
		}
	}

	waitCtx, cancel := context.WithTimeout(ctx, flagTimeout)
	defer cancel()
	r, err := l.Wait(waitCtx)
	if err != nil {
		return nil, err
	}

	data := map[string]any{"state": state, "code": r.Code, "login_proof": proof}
	if r.Error != "" {
		data["error"], data["error_description"] = r.Error, r.ErrorDescription
	}
	res, err = client.Operator().Write(base+"callback", data)
	if err != nil {
		return nil, fmt.Errorf("finishing the sign-in: %w", err)
	}
	inner, _ := res.Data["data"].(map[string]any)
	token, _ := inner["token"].(string)
	if token == "" {
		return nil, errors.New("finishing the sign-in: the server returned no session token")
	}
	expires, _ := dataString(res, "expire_at")
	exp, err := time.Parse(time.RFC3339Nano, expires)
	if err != nil {
		return nil, fmt.Errorf("finishing the sign-in: the session's expiry %q: %w", expires, err)
	}
	return &helpers.Session{Mount: base, Token: token, ExpiresAt: exp}, nil
}

// newBinding draws the login's secret and returns its binding (base64url of
// its SHA-256, sent to auth_url) and its proof (the secret, sent to callback).
// The secret never leaves this process before callback, so whoever captures
// the redirect cannot finish the login.
func newBinding() (binding, proof string, err error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", "", err
	}
	sum := sha256.Sum256(secret)
	return base64.RawURLEncoding.EncodeToString(sum[:]), base64.RawURLEncoding.EncodeToString(secret), nil
}

func dataString(res *api.Resource, key string) (string, bool) {
	if res == nil || res.Data == nil {
		return "", false
	}
	s, ok := res.Data[key].(string)
	return s, ok
}
