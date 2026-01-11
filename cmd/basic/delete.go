package basic

import (
	"encoding/json"
	"fmt"
	"os"

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
Usage: warden delete PATH

  Delete data at the given path. The path should be in the format
  "provider_mount/resource" or "auth/auth_mount/resource" or "sys/path/to/resource"
  and will be converted to the appropriate API path.

  Examples:

    Delete a JWT auth role:

      $ warden delete auth/jwt/role/developer

    Delete a provider:

      $ warden delete sys/providers/aws

    Delete a namespace:

      $ warden delete sys/namespaces/test
`,
		Args: cobra.ExactArgs(1),
		RunE: runDelete,
	}

	// Output format flag for delete
	deleteOutputFormat string
)

func init() {
	DeleteCmd.Flags().StringVarP(&deleteOutputFormat, "format", "f", "table", "Output format: table, json")
}

func runDelete(cmd *cobra.Command, args []string) error {
	path := args[0]

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
