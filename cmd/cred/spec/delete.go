package spec

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	deleteForce bool

	DeleteCmd = &cobra.Command{
		Use:           "delete <name>",
		Short:         "Delete a credential specification",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.ExactArgs(1),
		RunE:          runDelete,
	}
)

func init() {
	DeleteCmd.Flags().BoolVarP(&deleteForce, "force", "f", false, "Skip confirmation prompt")
}

func runDelete(cmd *cobra.Command, args []string) error {
	name := args[0]

	if !deleteForce {
		fmt.Printf("WARNING: This will permanently delete credential spec '%s'\n", name)
		fmt.Print("Are you sure? (yes/no): ")
		var response string
		fmt.Scanln(&response)

		if response != "yes" && response != "y" {
			fmt.Println("Deletion cancelled.")
			return nil
		}
	}

	c, err := helpers.Client()
	if err != nil {
		return err
	}

	err = c.Sys().DeleteCredentialSpec(name)
	if err != nil {
		return fmt.Errorf("error deleting credential spec: %w", err)
	}

	fmt.Printf("Success! Deleted credential spec: %s\n", name)
	return nil
}
