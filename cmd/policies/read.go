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
Usage: warden policy read <name>

  Reads a capability-based policy and prints its contents.

  Example:

    Read a policy:

      $ warden policy read my-policy
`,
	Args: cobra.ExactArgs(1),
	RunE: runRead,
}

func runRead(cmd *cobra.Command, args []string) error {
	name := args[0]
	if err := helpers.ValidatePath(name); err != nil {
		return err
	}

	c, err := helpers.Client()
	if err != nil {
		return err
	}

	policy, err := c.Sys().GetPolicy(name)
	if err != nil {
		return fmt.Errorf("error reading policy: %w", err)
	}

	if policy == nil {
		return fmt.Errorf("policy %q not found: %w", name, helpers.ErrNotFound)
	}

	data := map[string]any{
		"name":   name,
		"policy": policy.Policy,
	}

	return helpers.RenderMap(data, func() {
		fmt.Println(policy.Policy)
	})
}
