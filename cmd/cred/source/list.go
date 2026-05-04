package source

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var ListCmd = &cobra.Command{
	Use:           "list",
	Short:         "List all credential sources",
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE:          runList,
}

func runList(cmd *cobra.Command, args []string) error {
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	sources, err := c.Sys().ListCredentialSources()
	if err != nil {
		return fmt.Errorf("error listing credential sources: %w", err)
	}

	if len(sources) == 0 {
		return helpers.RenderList(nil, func() {
			fmt.Println("No credential sources found.")
		})
	}

	items := make([]map[string]any, 0, len(sources))
	for _, s := range sources {
		items = append(items, map[string]any{
			"name": s.Name,
			"type": s.Type,
		})
	}

	return helpers.RenderList(items, func() {
		headers := []string{"Name", "Type"}
		data := make([][]any, 0, len(items))
		for _, m := range items {
			data = append(data, []any{m["name"], m["type"]})
		}
		helpers.PrintTable(headers, data)
	})
}
