package providers

import "github.com/spf13/cobra"

var (
	ProvidersCmd = &cobra.Command{
		Use:   "provider",
		Short: "This command groups subcommands for managing Warden's providers.",
		Long: `
Usage: warden provider <subcommand> [options]

  This command groups subcommands for managing Warden's providers.
  Each provider behaves differently. Please see the documentation for
  more information.

  List all enabled providers:

      $ warden provider list

  Enable a new provider:

      $ warden provider enable --type=aws

  Please see the individual subcommand help for detailed usage information.
`,
	}
)


func init() {
	ProvidersCmd.AddCommand(EnableCmd)
	ProvidersCmd.AddCommand(DisableCmd)
	ProvidersCmd.AddCommand(ListCmd)
	ProvidersCmd.AddCommand(ReadCmd)
}