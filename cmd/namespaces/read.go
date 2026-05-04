package namespaces

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var ReadCmd = &cobra.Command{
	Use:           "read <path>",
	SilenceUsage:  true,
	SilenceErrors: true,
	Short:         "This command reads namespace information.",
	Long: `
Usage: warden namespace read <path>

  Reads detailed information about a specific namespace including its ID,
  path, and custom metadata.

  Read namespace information:

      $ warden namespace read my-team

  Read nested namespace:

      $ warden namespace read org/engineering

  Output as JSON:

      $ warden namespace read my-team -o json

  For more information about namespaces, please see the documentation.
`,
	Args: cobra.ExactArgs(1),
	RunE: runRead,
}

func runRead(cmd *cobra.Command, args []string) error {
	path := args[0]
	if err := helpers.ValidatePath(path); err != nil {
		return err
	}

	c, err := helpers.Client()
	if err != nil {
		return err
	}

	ns, err := c.Sys().GetNamespace(path)
	if err != nil {
		return fmt.Errorf("error reading namespace: %w", err)
	}

	data := map[string]any{
		"id":      ns.ID,
		"path":    ns.Path,
		"locked":  ns.Locked,
		"tainted": ns.Tainted,
		"uuid":    ns.Uuid,
	}
	if len(ns.CustomMetadata) > 0 {
		meta := make(map[string]any, len(ns.CustomMetadata))
		for k, v := range ns.CustomMetadata {
			meta[k] = v
		}
		data["custom_metadata"] = meta
	}

	return helpers.RenderMap(data, func() {
		headers := []string{"Key", "Value"}
		rows := [][]any{
			{"custom_metadata", formatCustomMetadata(ns.CustomMetadata)},
			{"id", ns.ID},
			{"locked", ns.Locked},
			{"path", ns.Path},
			{"tainted", ns.Tainted},
			{"uuid", ns.Uuid},
		}
		helpers.PrintTable(headers, rows)
	})
}

// formatCustomMetadata formats the custom metadata map as a sorted key=value string
func formatCustomMetadata(metadata map[string]string) string {
	if len(metadata) == 0 {
		return "n/a"
	}
	keys := make([]string, 0, len(metadata))
	for k := range metadata {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	pairs := make([]string, 0, len(keys))
	for _, k := range keys {
		pairs = append(pairs, fmt.Sprintf("%s=%s", k, metadata[k]))
	}
	return strings.Join(pairs, ", ")
}
