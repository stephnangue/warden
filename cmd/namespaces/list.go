package namespaces

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	listRecursive     bool
	listIncludeParent bool
	listFormat        string

	ListCmd = &cobra.Command{
		Use:           "list",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "This command lists all namespaces.",
		Long: `
Usage: warden namespace list [options]

  Lists all namespaces in the current namespace context. By default, it lists
  only direct child namespaces.

  List all namespaces:

      $ warden namespace list

  List all namespaces recursively:

      $ warden namespace list -r

  List namespaces including the parent:

      $ warden namespace list --include-parent

  List namespaces in table format:

      $ warden namespace list --format=table

  For more information about namespaces, please see the documentation.
`,
		RunE: runList,
	}
)

func init() {
	ListCmd.Flags().BoolVarP(&listRecursive, "recursive", "r", false, "Recursively list all descendant namespaces")
	ListCmd.Flags().BoolVar(&listIncludeParent, "include-parent", false, "Include the parent namespace in the result")
	ListCmd.Flags().StringVar(&listFormat, "format", "table", "Output format (table or json)")
}

func runList(cmd *cobra.Command, args []string) error {
	// Create the client
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	// List namespaces
	namespaces, err := c.Sys().ListNamespaces(listRecursive, listIncludeParent)
	if err != nil {
		return fmt.Errorf("error listing namespaces: %w", err)
	}

	if len(namespaces) == 0 {
		fmt.Println("No namespaces found.")
		return nil
	}

	// Display results based on format
	if listFormat == "json" {
		// TODO: Implement JSON output
		fmt.Println("JSON output not yet implemented")
		return nil
	}

	// Table format
	fmt.Printf("Found %d namespace(s):\n\n", len(namespaces))

	// Build table data
	headers := []string{"Path", "ID", "Metadata"}
	data := make([][]any, 0, len(namespaces))

	for _, ns := range namespaces {
		metadata := ""
		if len(ns.CustomMetadata) > 0 {
			metadata = fmt.Sprintf("%d key(s)", len(ns.CustomMetadata))
		}
		data = append(data, []any{ns.Path, ns.ID, metadata})
	}

	helpers.PrintTable(headers, data)
	return nil
}
