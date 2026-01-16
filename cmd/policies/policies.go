package policies

import (
	"github.com/spf13/cobra"
)

var PoliciesCmd = &cobra.Command{
	Use:   "policy",
	Short: "Interact with Warden policies",
	Long: `
The policy command groups subcommands for interacting with policies.
Policies control access to resources in Warden using capability-based permissions.

Examples:

  Create a policy from stdin:

    $ warden policy write my-policy - <<EOF
    path "secret/data/myapp/*" {
      capabilities = ["create", "read", "update", "delete", "list"]
    }
    EOF

  Read a policy:

    $ warden policy read my-policy

  List all policies:

    $ warden policy list

  Delete a policy:

    $ warden policy delete my-policy
`,
}

func init() {
	PoliciesCmd.AddCommand(WriteCmd)
	PoliciesCmd.AddCommand(ReadCmd)
	PoliciesCmd.AddCommand(ListCmd)
	PoliciesCmd.AddCommand(DeleteCmd)
}
