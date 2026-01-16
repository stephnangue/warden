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

  Deletes a capability-based policy.

  WARNING: This is a destructive operation and cannot be undone!

  By default, this command will ask for confirmation before deleting.
  Use the -f/--force flag to skip the confirmation prompt.

  Examples:

    Delete a policy (with confirmation):

      $ warden policy delete my-policy

    Delete a policy (skip confirmation):

      $ warden policy delete my-policy -f
`,
		Args: cobra.ExactArgs(1),
		RunE: runDelete,
	}
)

func init() {
	DeleteCmd.Flags().BoolVarP(&deleteForce, "force", "f", false, "Skip confirmation prompt")
}

func runDelete(cmd *cobra.Command, args []string) error {
	name := args[0]

	// Confirmation prompt (unless --force is used)
	if !deleteForce {
		fmt.Printf("Are you sure you want to delete policy '%s'? (yes/no): ", name)

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

	// Create the client
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	// Delete the policy
	err = c.Sys().DeletePolicy(name)
	if err != nil {
		return fmt.Errorf("error deleting policy: %w", err)
	}

	fmt.Printf("Success! Deleted policy: %s\n", name)
	return nil
}
