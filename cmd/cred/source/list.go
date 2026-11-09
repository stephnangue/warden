package source

import (
	"fmt"
	"strings"

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
		item := map[string]any{
			"name": s.Name,
			"type": s.Type,
		}
		if len(s.StoredSecrets) > 0 {
			item["stored_secrets"] = s.StoredSecrets
		}
		items = append(items, item)
	}

	return helpers.RenderList(items, func() {
		headers := []string{"Name", "Type", "Stored Secrets"}
		data := make([][]any, 0, len(sources))
		for _, s := range sources {
			data = append(data, []any{s.Name, s.Type, storedSecretsCell(s.StoredSecrets)})
		}
		helpers.PrintTable(headers, data)
	})
}

// storedSecretsCell renders a stored_secrets list for a table cell.
func storedSecretsCell(secrets []string) string {
	if len(secrets) == 0 {
		return "none"
	}
	return strings.Join(secrets, ", ")
}
