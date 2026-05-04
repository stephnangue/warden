package namespaces

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
		Use:           "delete <path>",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "This command deletes a namespace.",
		Long: `
Usage: warden namespace delete <path> [options]

  Deletes a namespace. The namespace must not contain any child namespaces
  before it can be deleted. All providers, auth methods, and roles within
  the namespace will be removed.

  WARNING: This is a destructive operation and cannot be undone!

  By default, this command will ask for confirmation before deleting.
  Use the -f/--force flag to skip the confirmation prompt.

  Delete a namespace (with confirmation):

      $ warden namespace delete my-team

  Delete a namespace (skip confirmation):

      $ warden namespace delete my-team -f

  Delete a nested namespace:

      $ warden namespace delete org/engineering

  For more information about namespaces, please see the documentation.
`,
		Args: cobra.ExactArgs(1),
		RunE: runDelete,
	}
)

func init() {
	DeleteCmd.Flags().BoolVarP(&deleteForce, "force", "f", false, "Skip confirmation prompt")
}

func runDelete(cmd *cobra.Command, args []string) error {
	path := args[0]
	if err := helpers.ValidatePath(path); err != nil {
		return err
	}

	// Confirmation prompt (unless --force is used)
	if !deleteForce {
		fmt.Printf("WARNING: This will permanently delete the namespace '%s' and all its contents.\n", path)
		fmt.Print("Are you sure you want to continue? (yes/no): ")

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

	// Delete the namespace
	err = c.Sys().DeleteNamespace(path)
	if err != nil {
		return fmt.Errorf("error deleting namespace: %w", err)
	}

	return helpers.RenderMap(map[string]any{"path": path, "deleted": true}, func() {
		fmt.Printf("Success! Deleted namespace: %s\n", path)
	})
}
