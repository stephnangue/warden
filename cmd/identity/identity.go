// Package identity implements `warden identity`, the namespace's identity
// objects: `warden identity group` manages the groups that grant roles (sudo
// on sys/identity/group); `warden identity entity` the entities of record and
// `warden identity alias` the native identities they claim (sudo on
// sys/identity/entity and sys/identity/lookup); and `warden identity usage`
// counts them against their caps (read on sys/identity/usage).
package identity

import "github.com/spf13/cobra"

var IdentityCmd = &cobra.Command{
	Use:   "identity",
	Short: "Manage identity objects: groups, entities and their native identities",
	Long: `
Usage: warden identity <subcommand> [options]

  Manage the identity objects of the current namespace.

  A group grants roles to its members; a virtual group's members are the
  callers whose verified facts match one of its rules, through an auth
  mount the rule's "mount" selector lists.

      $ warden identity group create deployers -json '{
          "type": "virtual",
          "roles": ["deploy"],
          "rules": [
            {
              "mount": ["auth/kubernetes/"],
              "service_account_namespace": ["ci"],
              "service_account_name": ["deployer"]
            }
          ]
        }'

  An entity is an agent of record: the humans accountable for it, its
  lifecycle state, and the native identities it presents through auth
  mounts (a service account, a SPIFFE ID, a JWT subject), each claimed by
  one entity.

      $ warden identity entity create billing-agent -json '{
          "description": "Reconciles supplier invoices",
          "sponsors": ["alice@corp.example"],
          "aliases": [
            { "mount": "auth/kubernetes/", "name": "system:serviceaccount:billing:agent" }
          ]
        }'

  Please see the individual subcommand help for detailed usage information.
`,
}

var EntityCmd = &cobra.Command{
	Use:   "entity",
	Short: "Manage the entities of record (sudo)",
	Long: `
Usage: warden identity entity <subcommand> [options]

  Manage the entities of the current namespace. An entity is an agent of
  record: the humans accountable for it (sponsors), what it does
  (description, profile), its lifecycle state (active, suspended, retired),
  and the native identities it claims. "governed_by" is derived: "warden"
  once it has a sponsor and a description.

      $ warden identity entity create billing-agent -json @billing-agent.json
      $ warden identity entity list -ungoverned
      $ warden identity entity read billing-agent
      $ warden identity entity update billing-agent -state=suspended
      $ warden identity entity lookup -mount=auth/kubernetes/ -name=system:serviceaccount:billing:agent

  A namespace's entities are capped; 'warden identity usage' shows the
  usage and the cap.

  Please see the individual subcommand help for detailed usage information.
`,
}

var AliasCmd = &cobra.Command{
	Use:   "alias",
	Short: "Claim, move and release native identities (sudo)",
	Long: `
Usage: warden identity alias <subcommand> [options]

  Manage which entity claims a native identity: the identity a credential
  presents through an auth mount, as the mount derives it (its
  alias_name_source). A native identity is claimed by one entity in a
  namespace.

      $ warden identity alias add -mount=auth/jwt/ -name=repo:corp/x:ref:refs/heads/main -to=billing-agent
      $ warden identity alias move -mount=auth/jwt/ -name=repo:corp/x:ref:refs/heads/main -to=invoice-agent
      $ warden identity alias remove -mount=auth/jwt/ -name=repo:corp/x:ref:refs/heads/main -from=invoice-agent

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
  verified facts match any one of the group's rules.

  A rule is a set of selectors, each a fact name with the values it may
  take; a caller must match one value of every selector. Every rule
  includes a "mount" selector, the auth mounts it trusts. "*" and "?" are
  globs ("*" never crosses "/", "**" does):

      $ warden identity group create ci-deployers -json '{
          "type": "virtual",
          "description": "CI deployers from GitHub and the ci cluster",
          "roles": ["deploy"],
          "rules": [
            {
              "mount": ["auth/github-oidc/"],
              "repo": ["acme/*"],
              "ref": ["refs/heads/main"]
            },
            {
              "mount": ["auth/kubernetes/"],
              "workload": ["system:serviceaccount:ci:deployer"]
            }
          ]
        }'

      $ warden identity group list -role deploy
      $ warden identity group read ci-deployers
      $ warden identity group delete ci-deployers

  A namespace's virtual groups, and the selectors across all their rules,
  are capped; 'warden identity usage' shows the usage and the caps.

  Please see the individual subcommand help for detailed usage information.
`,
}

func init() {
	IdentityCmd.AddCommand(GroupCmd)
	IdentityCmd.AddCommand(EntityCmd)
	IdentityCmd.AddCommand(AliasCmd)
	IdentityCmd.AddCommand(UsageCmd)
	GroupCmd.AddCommand(GroupCreateCmd)
	GroupCmd.AddCommand(GroupReadCmd)
	GroupCmd.AddCommand(GroupUpdateCmd)
	GroupCmd.AddCommand(GroupDeleteCmd)
	GroupCmd.AddCommand(GroupListCmd)
	EntityCmd.AddCommand(EntityCreateCmd)
	EntityCmd.AddCommand(EntityReadCmd)
	EntityCmd.AddCommand(EntityUpdateCmd)
	EntityCmd.AddCommand(EntityDeleteCmd)
	EntityCmd.AddCommand(EntityListCmd)
	EntityCmd.AddCommand(EntityLookupCmd)
	AliasCmd.AddCommand(AliasAddCmd)
	AliasCmd.AddCommand(AliasMoveCmd)
	AliasCmd.AddCommand(AliasRemoveCmd)
}
