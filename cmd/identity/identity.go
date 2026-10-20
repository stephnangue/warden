// Package identity implements `warden identity`, the namespace's identity
// objects. Its one command group today is `warden identity group`: create,
// read, update, delete and list the groups that grant roles. Every command
// needs a token with sudo on sys/identity.
package identity

import "github.com/spf13/cobra"

var IdentityCmd = &cobra.Command{
	Use:   "identity",
	Short: "Manage identity objects: groups",
	Long: `
Usage: warden identity <subcommand> [options]

  Manage the identity objects of the current namespace. A group grants
  roles to its members; a virtual group's members are the callers whose
  verified facts match one of its selectors, through an auth mount the
  selector lists.

      $ warden identity group create deployers -json '{
          "type": "virtual",
          "roles": ["deploy"],
          "selectors": [
            {
              "mount": ["auth/kubernetes/"],
              "service_account_namespace": ["ci"],
              "service_account_name": ["deployer"]
            }
          ]
        }'

  Please see the individual subcommand help for detailed usage information.
`,
}

var GroupCmd = &cobra.Command{
	Use:   "group",
	Short: "Manage the groups that grant roles (sudo)",
	Long: `
Usage: warden identity group <subcommand> [options]

  Manage the groups of the current namespace. A group lists the roles its
  membership grants. Its "type" says where membership comes from and never
  changes; "virtual" is the one type today: a caller is a member when its
  verified facts match any one of the group's selectors.

  Every selector names "mount", the auth mounts it trusts, plus the facts
  those mounts verified, each with the values it may take ("*" and "?"
  are globs; "*" never crosses "/", "**" does):

      $ warden identity group create ci-deployers -json '{
          "type": "virtual",
          "description": "CI deployers from GitHub and the ci cluster",
          "roles": ["deploy"],
          "selectors": [
            {
              "mount": ["auth/github-oidc/"],
              "repo": ["acme/*"],
              "ref": ["refs/heads/main"]
            },
            {
              "mount": ["auth/kubernetes/"],
              "workload": ["system:serviceaccount:ci:deployer"]
            }
          ],
          "max_age": "10m"
        }'

      $ warden identity group list -role deploy
      $ warden identity group read ci-deployers
      $ warden identity group delete ci-deployers

  Please see the individual subcommand help for detailed usage information.
`,
}

func init() {
	IdentityCmd.AddCommand(GroupCmd)
	GroupCmd.AddCommand(GroupCreateCmd)
	GroupCmd.AddCommand(GroupReadCmd)
	GroupCmd.AddCommand(GroupUpdateCmd)
	GroupCmd.AddCommand(GroupDeleteCmd)
	GroupCmd.AddCommand(GroupListCmd)
}
