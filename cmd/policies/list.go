package policies

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var ListCmd = &cobra.Command{
	Use:           "list",
	SilenceUsage:  true,
	SilenceErrors: true,
	Short:         "List all policies",
	Long: `
Usage: warden policy list [flags]

  Lists policies in the current namespace. Use -type to select which kind:
  "cbp" (default) or "mcp".

  Examples:

    List capability-based policies:

      $ warden policy list

    List MCP policies:

      $ warden policy list -type mcp
`,
	Args: cobra.NoArgs,
	RunE: runList,
}

func init() {
	addTypeFlag(ListCmd)
}

func runList(cmd *cobra.Command, args []string) error {
	pType, err := resolvePolicyType()
	if err != nil {
		return err
	}

	c, err := helpers.Client()
	if err != nil {
		return err
	}

	policies, err := c.Sys().ListPoliciesOfType(pType)
	if err != nil {
		return fmt.Errorf("error listing policies: %w", err)
	}

	if len(policies) == 0 {
		return helpers.RenderStrings(nil, func() {
			fmt.Printf("No %s policies found\n", pType)
		})
	}

	return helpers.RenderStrings(policies, func() {
		fmt.Printf("%s policies\n", strings.ToUpper(pType))
		for _, policy := range policies {
			fmt.Printf("  %s\n", policy)
		}
	})
}
