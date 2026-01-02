package namespaces

import "github.com/spf13/cobra"

var (
	NamespacesCmd = &cobra.Command{
		Use:   "namespace",
		Short: "This command groups subcommands for managing Warden's namespaces.",
		Long: `
Usage: warden namespace <subcommand> [options]

  This command groups subcommands for managing Warden's namespaces.
  Namespaces allow you to isolate and organize your secrets and
  configurations in a multi-tenant environment.

  List all namespaces:

      $ warden namespace list

  Create a new namespace:

      $ warden namespace create my-team

  Read namespace information:

      $ warden namespace read my-team

  Please see the individual subcommand help for detailed usage information.
`,
	}
)

func init() {
	NamespacesCmd.AddCommand(CreateCmd)
	NamespacesCmd.AddCommand(ListCmd)
	NamespacesCmd.AddCommand(ReadCmd)
	NamespacesCmd.AddCommand(UpdateCmd)
	NamespacesCmd.AddCommand(DeleteCmd)
}
