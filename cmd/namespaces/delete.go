package namespaces

import (
	"fmt"

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

  Delete a namespace:

      $ warden namespace delete my-team

  Delete a nested namespace:

      $ warden namespace delete org/engineering

  For more information about namespaces, please see the documentation.
`,
		Args: cobra.ExactArgs(1),
		RunE: runDelete,
	}
)

func init() {
	DeleteCmd.Flags().BoolVar(&deleteForce, "force", false, "Skip confirmation prompt")
}

func runDelete(cmd *cobra.Command, args []string) error {
	path := args[0]

	// Confirmation prompt (unless --force is used)
	if !deleteForce {
		fmt.Printf("WARNING: This will permanently delete the namespace '%s' and all its contents.\n", path)
		fmt.Print("Are you sure you want to continue? (yes/no): ")

		var response string
		fmt.Scanln(&response)

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

	fmt.Printf("Success! Deleted namespace: %s\n", path)
	return nil
}
