package providers

import "github.com/spf13/cobra"

var (
	ProvidersCmd = &cobra.Command{
		Use:   "providers",
		Short: "This command groups subcommands for managing Warden's providers.",
		Long: `
Usage: warden providers <subcommand> [options]

  This command groups subcommands for managing Warden's providers.
  Each provider behaves differently. Please see the documentation for
  more information.

  List all enabled providers:

      $ warden providers list

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
	ProvidersCmd.AddCommand(TuneCmd)
}