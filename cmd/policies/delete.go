package policies

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	deleteForce bool

	DeleteCmd = &cobra.Command{
		Use:           "delete <name>",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Delete a policy",
		Long: `
Usage: warden policy delete <name> [flags]

  Deletes a policy. Use -type to select which kind: "cbp" (default) or "mcp".

  WARNING: This is a destructive operation and cannot be undone!

  By default, this command will ask for confirmation before deleting.
  Use the -f/-force flag to skip the confirmation prompt.

  Examples:

    Delete a capability-based policy (with confirmation):

      $ warden policy delete my-policy

    Delete an MCP policy:

      $ warden policy delete -type mcp github-tools

    Delete a policy (skip confirmation):

      $ warden policy delete my-policy -f
`,
		Args: cobra.ExactArgs(1),
		RunE: runDelete,
	}
)

func init() {
	DeleteCmd.Flags().BoolVarP(&deleteForce, "force", "f", false, "Skip confirmation prompt")
	addTypeFlag(DeleteCmd)
}

func runDelete(cmd *cobra.Command, args []string) error {
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

	if helpers.ResolveDryRun() {
		return helpers.DryRun(c, "DELETE", "sys/policies/"+pType+"/{name}", nil)
	}

	// Confirmation prompt (unless -force is used)
	if !deleteForce {
		fmt.Printf("Are you sure you want to delete %s policy '%s'? (yes/no): ", pType, name)

		reader := bufio.NewReader(os.Stdin)
		response, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read confirmation: %w", err)
		}

		response = strings.TrimSpace(strings.ToLower(response))
		if response != "yes" && response != "y" {
			fmt.Println("Deletion cancelled.")
			return nil
		}
	}

	// Delete the policy
	err = c.Sys().DeletePolicyOfType(pType, name)
	if err != nil {
		return fmt.Errorf("error deleting policy: %w", err)
	}

	return helpers.RenderMap(map[string]any{"name": name, "type": pType, "deleted": true}, func() {
		fmt.Printf("Success! Deleted %s policy: %s\n", pType, name)
	})
}
