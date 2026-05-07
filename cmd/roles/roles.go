// Package roles implements `warden role`, the agent-facing role-introspection
// command group. The list subcommand hits the server endpoint at
// /v1/sys/introspect/roles which fans out to every auth mount of the caller's
// identity type (JWT or cert) in the current namespace and returns the union
// of roles each mount reports the identity can assume.
package roles

import "github.com/spf13/cobra"

var RolesCmd = &cobra.Command{
	Use:   "role",
	Short: "Discover and manage Warden roles",
	Long: `
Usage: warden role <subcommand> [options]

  Discover and manage Warden roles.

  List the roles the presented identity can assume:

      $ warden role list

  Please see the individual subcommand help for detailed usage information.
`,
}

func init() {
	RolesCmd.AddCommand(ListCmd)
}
