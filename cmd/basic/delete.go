package basic

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	DeleteCmd = &cobra.Command{
		Use:           "delete",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Delete data at a path",
		Long: `
Usage: warden delete [PATH] [flags]

  Delete data at the given path. The PATH may be supplied either
  positionally or via --path (pick one — combining both is rejected).
  The path should be in the format "provider_mount/resource" or
  "auth/auth_mount/resource" or "sys/path/to/resource" and will be
  converted to the appropriate API path.

  By default, this command will ask for confirmation before deleting.
  Use the -f/--force flag to skip the confirmation prompt.

  Examples:

    Delete a JWT auth role (with confirmation):

      $ warden delete auth/jwt/role/developer
      $ warden delete --path=auth/jwt/role/developer

    Delete a provider (skip confirmation):

      $ warden delete sys/providers/aws -f

    Delete a namespace:

      $ warden delete sys/namespaces/test
`,
		Args: cobra.MaximumNArgs(1),
		RunE: runDelete,
	}

	deleteForce bool
	deletePath  string
)

func init() {
	DeleteCmd.Flags().BoolVarP(&deleteForce, "force", "f", false, "Skip confirmation prompt")
	DeleteCmd.Flags().StringVar(&deletePath, "path", "", "API path (alternative to the positional PATH argument)")
}

func runDelete(cmd *cobra.Command, args []string) error {
	path, err := helpers.RequirePath(args, deletePath)
	if err != nil {
		return err
	}
	if err := helpers.ValidatePath(path); err != nil {
		return err
	}

	// Create the client
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	// --dry-run: validate the path resolves to a known DELETE-supporting
	// schema entry and stop before any prompt or HTTP call. Skipping the
	// confirmation prompt is intentional — a non-mutating preview shouldn't
	// require interactive consent.
	if helpers.ResolveDryRun() {
		return helpers.DryRun(c, "DELETE", path, nil)
	}

	// Ask for confirmation unless -y flag is used
	if !deleteForce {
		fmt.Printf("Are you sure you want to delete '%s'? (yes/no): ", path)
		reader := bufio.NewReader(os.Stdin)
		response, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read confirmation: %w", err)
		}

		response = strings.TrimSpace(strings.ToLower(response))
		if response != "yes" && response != "y" {
			fmt.Println("Delete cancelled")
			return nil
		}
	}

	// Delete at the path
	resource, err := c.Operator().Delete(path)
	if err != nil {
		return fmt.Errorf("failed to delete %s: %w", path, err)
	}

	if resource == nil || resource.Data == nil {
		return helpers.RenderMap(map[string]any{"path": path, "deleted": true}, func() {
			fmt.Printf("Successfully deleted: %s\n", path)
		})
	}

	return helpers.RenderMap(resource.Data, func() {
		if msg, ok := resource.Data["message"]; ok {
			fmt.Println(msg)
			return
		}
		helpers.PrintMapAsTable(resource.Data)
	})
}
