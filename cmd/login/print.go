package login

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var PrintCmd = &cobra.Command{
	Use:   "print",
	Short: "Print values of the current session",
	Long: `
Usage: warden print <subcommand>

  Prints values of the current warden login session.

  A session whose token is bound to a key (the oidc mount's dpop_enabled, on
  by default) is usable only by warden commands, which prove the key on every
  request: its token alone is refused.

  Example:

      $ warden print token
`,
}

var printTokenCmd = &cobra.Command{
	Use:           "token",
	SilenceUsage:  true,
	SilenceErrors: true,
	Short:         "Print the session token of the current Warden address and namespace",
	Args:          cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		_, s, err := helpers.RequireSession()
		if err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), s.Token)
		if s.Bound() {
			fmt.Fprintln(cmd.ErrOrStderr(), "Note: this session's token is bound to the key warden login keeps with it; it is refused without a proof of that key.")
		}
		return nil
	},
}

func init() {
	PrintCmd.AddCommand(printTokenCmd)
}
