package basic

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	ListCmd = &cobra.Command{
		Use:           "list",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "List data from a path",
		Long: `
Usage: warden list PATH

  List data from the given path. The path should be in the format
  "provider_mount/resource" or "auth/auth_mount/resource" or "sys/path/to/resource"
  and will be converted to the appropriate API path.

  Examples:

    List JWT auth roles:

      $ warden list auth/jwt/role

    List providers:

      $ warden list sys/providers

    List namespaces:

      $ warden list sys/namespaces
`,
		Args: cobra.ExactArgs(1),
		RunE: runList,
	}

	// Output format flag for list
	listOutputFormat string
)

func init() {
	ListCmd.Flags().StringVarP(&listOutputFormat, "format", "f", "table", "Output format: table, json")
}

func runList(cmd *cobra.Command, args []string) error {
	path := args[0]

	// Create the client
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	// List from the path
	resource, err := c.Operator().List(path)
	if err != nil {
		return fmt.Errorf("failed to list from %s: %w", path, err)
	}

	if resource == nil || resource.Data == nil {
		fmt.Fprintf(os.Stderr, "No data found at path: %s\n", path)
		return nil
	}

	switch listOutputFormat {
	case "json":
		return outputListJSON(resource.Data)
	case "table":
		printKeys(resource.Data)
		return nil
	default:
		return fmt.Errorf("unknown output format: %s", listOutputFormat)
	}
}

func outputListJSON(data map[string]any) error {
	output, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}
	fmt.Println(string(output))
	return nil
}

// printKeys prints the keys in the format:
//
//	Keys
//	  key1
//	  key2
func printKeys(data map[string]any) {
	keys, ok := data["keys"]
	if !ok {
		fmt.Println("No keys found")
		return
	}

	// Check for nil keys
	if keys == nil {
		fmt.Println("No keys found")
		return
	}

	// Handle both []string and []interface{} types
	switch v := keys.(type) {
	case []string:
		if len(v) == 0 {
			fmt.Println("No keys found")
			return
		}
		fmt.Println("Keys")
		for _, key := range v {
			fmt.Printf("  %s\n", key)
		}
	case []interface{}:
		if len(v) == 0 {
			fmt.Println("No keys found")
			return
		}
		fmt.Println("Keys")
		for _, key := range v {
			fmt.Printf("  %v\n", key)
		}
	default:
		fmt.Println("No keys found")
	}
}
