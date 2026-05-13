package providers

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
	Short:         "Lists the enabled providers on the Warden server",
	Long: `
Usage: warden provider list

  Lists the enabled providers on the Warden server. This command also
  outputs information about the enabled path including a
  human-friendly descriptions.

  List all enabled providers:

      $ warden provider list
`,
	RunE: runList,
}

func runList(cmd *cobra.Command, args []string) error {
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	mounts, err := c.Sys().ListMounts()
	if err != nil {
		return fmt.Errorf("error listing providers: %w", err)
	}

	if len(mounts) == 0 {
		return helpers.RenderList(nil, func() {
			fmt.Println("No providers enabled")
		})
	}

	paths := make([]string, 0, len(mounts))
	for path := range mounts {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	items := make([]map[string]any, 0, len(paths))
	for _, path := range paths {
		mount := mounts[path]
		items = append(items, map[string]any{
			"path":        path,
			"type":        mount.Type,
			"accessor":    mount.Accessor,
			"description": mount.Description,
			"mount_url":   mount.MountURL,
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
