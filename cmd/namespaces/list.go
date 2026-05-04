package namespaces

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	listRecursive     bool
	listIncludeParent bool

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

      $ warden namespace list -R

  List namespaces including the parent:

      $ warden namespace list --include-parent

  Output as JSON:

      $ warden namespace list -o json

  For more information about namespaces, please see the documentation.
`,
		RunE: runList,
	}
)

func init() {
	ListCmd.Flags().BoolVarP(&listRecursive, "recursive", "R", false, "Recursively list all descendant namespaces")
	ListCmd.Flags().BoolVar(&listIncludeParent, "include-parent", false, "Include the parent namespace in the result")
}

func runList(cmd *cobra.Command, args []string) error {
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	namespaces, err := c.Sys().ListNamespaces(listRecursive, listIncludeParent)
	if err != nil {
		return fmt.Errorf("error listing namespaces: %w", err)
	}

	if len(namespaces) == 0 {
		return helpers.RenderList(nil, func() {
			fmt.Println("No namespaces found.")
		})
	}

	items := make([]map[string]any, 0, len(namespaces))
	for _, ns := range namespaces {
		item := map[string]any{
			"path": ns.Path,
			"id":   ns.ID,
		}
		if len(ns.CustomMetadata) > 0 {
			meta := make(map[string]any, len(ns.CustomMetadata))
			for k, v := range ns.CustomMetadata {
				meta[k] = v
			}
			item["custom_metadata"] = meta
		}
		items = append(items, item)
	}

	return helpers.RenderList(items, func() {
		fmt.Printf("Found %d namespace(s):\n\n", len(namespaces))
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
	})
}
