package audit

import (
	"fmt"
	"sort"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var ListCmd = &cobra.Command{
	Use:           "list",
	SilenceUsage:  true,
	SilenceErrors: true,
	Short:         "Lists the enabled audit devices on the Warden server",
	Long: `
Usage: warden audit list

  Lists the enabled audit devices on the Warden server. This command also
  outputs information about the enabled path including type, accessor,
  and human-friendly descriptions.

  List all enabled audit devices:

      $ warden audit list
`,
	RunE: runList,
}

func runList(cmd *cobra.Command, args []string) error {
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	audits, err := c.Sys().ListAudit()
	if err != nil {
		return fmt.Errorf("error listing audit devices: %w", err)
	}

	if len(audits) == 0 {
		return helpers.RenderList(nil, func() {
			fmt.Println("No audit devices enabled")
		})
	}

	paths := make([]string, 0, len(audits))
	for path := range audits {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	items := make([]map[string]any, 0, len(paths))
	for _, path := range paths {
		a := audits[path]
		items = append(items, map[string]any{
			"path":        path,
			"type":        a.Type,
			"accessor":    a.Accessor,
			"description": a.Description,
		})
	}

	return helpers.RenderList(items, func() {
		headers := []string{"Path", "Type", "Accessor", "Description"}
		data := make([][]any, 0, len(items))
		for _, m := range items {
			data = append(data, []any{m["path"], m["type"], m["accessor"], m["description"]})
		}
		helpers.PrintTable(headers, data)
	})
}
