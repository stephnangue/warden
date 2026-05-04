package policies

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var ListCmd = &cobra.Command{
	Use:           "list",
	SilenceUsage:  true,
	SilenceErrors: true,
	Short:         "List all policies",
	Long: `
Usage: warden policy list

  Lists all capability-based policies in the current namespace.

  Example:

    List all policies:

      $ warden policy list
`,
	Args: cobra.NoArgs,
	RunE: runList,
}

func runList(cmd *cobra.Command, args []string) error {
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	policies, err := c.Sys().ListPolicies()
	if err != nil {
		return fmt.Errorf("error listing policies: %w", err)
	}

	if len(policies) == 0 {
		return helpers.RenderStrings(nil, func() {
			fmt.Println("No policies found")
		})
	}

	return helpers.RenderStrings(policies, func() {
		fmt.Println("Policies")
		for _, policy := range policies {
			fmt.Printf("  %s\n", policy)
		}
	})
}
