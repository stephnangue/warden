package source

import (
	"fmt"

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
		for key, value := range source.Config {
			// Mask sensitive values
			displayValue := value
			if key == "token" || key == "password" || key == "secret" || key == "secret_id" {
				displayValue = "***********"
			}
			data = append(data, []any{fmt.Sprintf("  %s", key), displayValue})
		}
	}

	helpers.PrintTable(headers, data)
	return nil
}
