// Package roles implements `warden role`. The list subcommand serves both
// sides: by default it hits /v1/sys/introspect/roles, which returns the roles
// of the current namespace a group grants the caller's identity (JWT or cert)
// at the auth mount each role is reached through; with -all it lists
// every role of the namespace through /v1/sys/roles. create, read, update and
// delete manage those roles and need sudo.
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

  Create a role in the current namespace (sudo):

      $ warden role create deploy -json '{
          "description": "Deploys from acme CI",
          "policies": ["deploy"],
          "cred_spec_name": "deploy-role",
          "provider_path": "aws/"
        }'

  List every role of the namespace (sudo):

      $ warden role list -all

  Choose the role your warden login session runs under:

      $ warden role use

  Please see the individual subcommand help for detailed usage information.
`,
}

func init() {
	RolesCmd.AddCommand(ListCmd)
	RolesCmd.AddCommand(CreateCmd)
	RolesCmd.AddCommand(ReadCmd)
	RolesCmd.AddCommand(UpdateCmd)
	RolesCmd.AddCommand(DeleteCmd)
	RolesCmd.AddCommand(UseCmd)
}
