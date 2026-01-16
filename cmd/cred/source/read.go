package source

import (
	"fmt"
	"sort"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var ReadCmd = &cobra.Command{
	Use:           "read <name>",
	Short:         "Read a credential source",
	SilenceUsage:  true,
	SilenceErrors: true,
	Args:          cobra.ExactArgs(1),
	RunE:          runRead,
}

func runRead(cmd *cobra.Command, args []string) error {
	name := args[0]

	c, err := helpers.Client()
	if err != nil {
		return err
	}

	source, err := c.Sys().GetCredentialSource(name)
	if err != nil {
		return fmt.Errorf("error reading credential source %s: %w", name, err)
	}

	headers := []string{"Key", "Value"}
	data := [][]any{
		{"Name", source.Name},
		{"Type", source.Type},
	}

	if len(source.Config) > 0 {
		data = append(data, []any{"Configuration", ""})

		// Sort config keys alphabetically
		keys := make([]string, 0, len(source.Config))
		for key := range source.Config {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		for _, key := range keys {
			// Server already masks sensitive values
			data = append(data, []any{fmt.Sprintf("  %s", key), source.Config[key]})
		}
	}

	helpers.PrintTable(headers, data)
	return nil
}
