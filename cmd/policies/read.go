package policies

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var ReadCmd = &cobra.Command{
	Use:           "read <name>",
	SilenceUsage:  true,
	SilenceErrors: true,
	Short:         "Read a policy",
	Long: `
Usage: warden policy read <name> [flags]

  Reads a policy and prints its contents. Use -type to select which kind:
  "cbp" (default) or "mcp".

  Examples:

    Read a capability-based policy:

      $ warden policy read my-policy

    Read an MCP policy:

      $ warden policy read -type mcp github-tools
`,
	Args: cobra.ExactArgs(1),
	RunE: runRead,
}

func init() {
	addTypeFlag(ReadCmd)
}

func runRead(cmd *cobra.Command, args []string) error {
	name := args[0]
	if err := helpers.ValidatePath(name); err != nil {
		return err
	}

	pType, err := resolvePolicyType()
	if err != nil {
		return err
	}

	c, err := helpers.Client()
	if err != nil {
		return err
	}

	policy, err := c.Sys().GetPolicyOfType(pType, name)
	if err != nil {
		return fmt.Errorf("error reading policy: %w", err)
	}

	if policy == nil {
		return fmt.Errorf("%s policy %q not found: %w", pType, name, helpers.ErrNotFound)
	}

	data := map[string]any{
		"name":   name,
		"type":   pType,
		"policy": policy.Policy,
	}

	return helpers.RenderMap(data, func() {
		fmt.Println(policy.Policy)
	})
}
