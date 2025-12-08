package auth

import "github.com/spf13/cobra"

var (
	AuthCmd = &cobra.Command{
		Use:   "auth",
		Short: "This command groups subcommands for managing Warden's auth methods.",
		Long: `
Usage: warden auth <subcommand> [options]

  This command groups subcommands for managing Warden's auth methods.
  Each auth method behaves differently. Please see the documentation for
  more information.

  List all enabled auth methods:

      $ warden auth list

  Enable a new auth method:

      $ warden auth enable --type=jwt

  Please see the individual subcommand help for detailed usage information.
`,
	}
)


func init() {
	AuthCmd.AddCommand(EnableCmd)
	AuthCmd.AddCommand(DisableCmd)
	AuthCmd.AddCommand(ListCmd)
	AuthCmd.AddCommand(ReadCmd)
	AuthCmd.AddCommand(TuneCmd)
}
