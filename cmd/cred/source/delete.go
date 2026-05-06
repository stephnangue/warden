package source

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	deleteForce bool

	DeleteCmd = &cobra.Command{
		Use:           "delete <name>",
		Short:         "Delete a credential source",
		Long:          `Deletes a credential source. This will fail if any credential specs reference this source.`,
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
	if err := helpers.ValidatePath(name); err != nil {
		return err
	}

	c, err := helpers.Client()
	if err != nil {
		return err
	}

	if helpers.ResolveDryRun() {
		return helpers.DryRun(c, "DELETE", "sys/cred/sources/{name}", nil)
	}

	if !deleteForce {
		fmt.Printf("WARNING: This will permanently delete credential source '%s'\n", name)
		fmt.Println("This will fail if any credential specs reference this source.")
		fmt.Print("Are you sure? (yes/no): ")
		var response string
		fmt.Scanln(&response)

		if response != "yes" && response != "y" {
			fmt.Println("Deletion cancelled.")
			return nil
		}
	}

	err = c.Sys().DeleteCredentialSource(name)
	if err != nil {
		return fmt.Errorf("error deleting credential source: %w", err)
	}

	return helpers.RenderMap(map[string]any{"name": name, "deleted": true}, func() {
		fmt.Printf("Success! Deleted credential source: %s\n", name)
	})
}
