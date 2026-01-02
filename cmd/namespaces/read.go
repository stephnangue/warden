package namespaces

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	readFormat string

	ReadCmd = &cobra.Command{
		Use:           "read <path>",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "This command reads namespace information.",
		Long: `
Usage: warden namespace read <path> [options]

  Reads detailed information about a specific namespace including its ID,
  path, and custom metadata.

  Read namespace information:

      $ warden namespace read my-team

  Read nested namespace:

      $ warden namespace read org/engineering

  Output in JSON format:

      $ warden namespace read my-team --format=json

  For more information about namespaces, please see the documentation.
`,
		Args: cobra.ExactArgs(1),
		RunE: runRead,
	}
)

func init() {
	ReadCmd.Flags().StringVar(&readFormat, "format", "table", "Output format (table or json)")
}


func runRead(cmd *cobra.Command, args []string) error {
	path := args[0]

	// Create the client
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	// Read namespace
	ns, err := c.Sys().GetNamespace(path)
	if err != nil {
		return fmt.Errorf("error reading namespace: %w", err)
	}

	// Display results based on format
	if readFormat == "json" {
		// TODO: Implement JSON output
		fmt.Println("JSON output not yet implemented")
		return nil
	}

	// Format custom metadata
	customMetadataStr := formatCustomMetadata(ns.CustomMetadata)

	// Create ordered data rows
	headers := []string{"Key", "Value"}
	data := make([][]any, 0, 6)
	data = append(data, []any{"custom_metadata", customMetadataStr})
	data = append(data, []any{"id", ns.ID})
	data = append(data, []any{"locked", ns.Locked})
	data = append(data, []any{"path", ns.Path})
	data = append(data, []any{"tainted", ns.Tainted})
	data = append(data, []any{"uuid", ns.Uuid})
	helpers.PrintTable(headers, data)

	return nil
}

// formatCustomMetadata formats the custom metadata map as a sorted key=value string
func formatCustomMetadata(metadata map[string]string) string {
	if len(metadata) == 0 {
		return "n/a"
	}

	// Get keys and sort them
	keys := make([]string, 0, len(metadata))
	for k := range metadata {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Build formatted string
	pairs := make([]string, 0, len(keys))
	for _, k := range keys {
		pairs = append(pairs, fmt.Sprintf("%s=%s", k, metadata[k]))
	}

	return strings.Join(pairs, ", ")
}
