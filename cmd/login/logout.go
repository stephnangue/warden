package login

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var LogoutCmd = &cobra.Command{
	Use:           "logout",
	SilenceUsage:  true,
	SilenceErrors: true,
	Short:         "Forget the session of the current Warden address and namespace",
	Long: `
Usage: warden logout

  Deletes the session warden login saved for the current Warden address and
  namespace (or, when the namespace has none, the nearest parent's, which is
  the one commands use there), and the key it keeps in the OS keystore. The
  session token itself stays valid until it
  expires: a session cannot be revoked before; disabling its auth mount ends
  every session it issued.

  Example:

      $ warden logout
`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		client, err := helpers.NewClientWithoutSession()
		if err != nil {
			return err
		}
		addr, err := helpers.NormalizeAddr(client.Address())
		if err != nil {
			return err
		}
		ns := helpers.NormalizeNamespace(client.Namespace())
		stderr := cmd.ErrOrStderr()
		s, err := helpers.FindSession(addr, ns)
		if err != nil {
			// A file that cannot be read is still removed, with any key the
			// keystore holds for it: logout is how they are cleared.
			_ = helpers.DeleteSessionKey(&helpers.Session{Addr: addr, Namespace: ns, KeyStore: helpers.KeyStoreOS})
			if derr := helpers.DeleteSession(addr, ns); derr != nil {
				return fmt.Errorf("%w (and removing it failed: %v)", err, derr)
			}
			fmt.Fprintf(stderr, "Removed the session of namespace %s, which could not be read: %v\n", helpers.DisplayNamespace(ns), err)
			return nil
		}
		if s == nil {
			fmt.Fprintf(stderr, "No session for %s (namespace %s).\n", addr, helpers.DisplayNamespace(ns))
			return nil
		}
		// The file goes whatever becomes of the key: it holds the ticket, and a
		// key left behind is useless without it.
		if err := helpers.DeleteSession(s.Addr, s.Namespace); err != nil {
			return err
		}
		if err := helpers.DeleteSessionKey(s); err != nil {
			fmt.Fprintf(stderr, "Warning: %v\n", err)
		}
		fmt.Fprintf(stderr, "Signed out of %s (namespace %s). The session token stays valid until %s.\n",
			s.Addr, helpers.DisplayNamespace(s.Namespace), s.ExpiresAt.Local().Format("15:04"))
		return nil
	},
}
