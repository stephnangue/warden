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

  Prints values of the current warden login session, for other tools.

  Example:

      $ curl -H "Authorization: Bearer $(warden print token)" "$WARDEN_ADDR/v1/sys/introspect/roles"
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
		return nil
	},
}

func init() {
	PrintCmd.AddCommand(printTokenCmd)
}
