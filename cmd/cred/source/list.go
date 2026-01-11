package source

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	listFormat string

	ListCmd = &cobra.Command{
		Use:           "list",
		Short:         "List all credential sources",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE:          runList,
	}
)

func init() {
	ListCmd.Flags().StringVar(&listFormat, "format", "table", "Output format (table or json)")
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
		fmt.Println("No credential sources found.")
		return nil
	}

	headers := []string{"Name", "Type"}
	data := make([][]any, 0, len(sources))

	for _, source := range sources {
		data = append(data, []any{
			source.Name,
			source.Type,
		})
	}

	helpers.PrintTable(headers, data)
	return nil
}
