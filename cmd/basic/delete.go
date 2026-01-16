package basic

import (
	"bufio"
	"encoding/json"
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
Usage: warden delete PATH [flags]

  Delete data at the given path. The path should be in the format
  "provider_mount/resource" or "auth/auth_mount/resource" or "sys/path/to/resource"
  and will be converted to the appropriate API path.

  By default, this command will ask for confirmation before deleting.
  Use the -f/--force flag to skip the confirmation prompt.

  Examples:

    Delete a JWT auth role (with confirmation):

      $ warden delete auth/jwt/role/developer

    Delete a provider (skip confirmation):

      $ warden delete sys/providers/aws -f

    Delete a namespace:

      $ warden delete sys/namespaces/test
`,
		Args: cobra.ExactArgs(1),
		RunE: runDelete,
	}

	// Output format flag for delete
	deleteOutputFormat string
	// Force flag to skip confirmation
	deleteForce bool
)

func init() {
	DeleteCmd.Flags().StringVarP(&deleteOutputFormat, "format", "", "table", "Output format: table, json")
	DeleteCmd.Flags().BoolVarP(&deleteForce, "force", "f", false, "Skip confirmation prompt")
}

func runDelete(cmd *cobra.Command, args []string) error {
	path := args[0]

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

	// Create the client
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	// Delete at the path
	resource, err := c.Operator().Delete(path)
	if err != nil {
		return fmt.Errorf("failed to delete %s: %w", path, err)
	}

	// Handle response
	if resource == nil || resource.Data == nil {
		fmt.Printf("Successfully deleted: %s\n", path)
		return nil
	}

	switch deleteOutputFormat {
	case "json":
		return outputDeleteJSON(resource.Data)
	case "table":
		// Check if there's a message in the response
		if msg, ok := resource.Data["message"]; ok {
			fmt.Println(msg)
		} else {
			helpers.PrintMapAsTable(resource.Data)
		}
		return nil
	default:
		return fmt.Errorf("unknown output format: %s", deleteOutputFormat)
	}
}

func outputDeleteJSON(data map[string]any) error {
	output, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}
	fmt.Println(string(output))
	return nil
}

// PrintSuccessMessage prints a simple success message to stdout
func PrintSuccessMessage(path string) {
	fmt.Fprintf(os.Stdout, "Success! Deleted: %s\n", path)
}
