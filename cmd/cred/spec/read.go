package spec

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var ReadCmd = &cobra.Command{
	Use:           "read <name>",
	Short:         "Read a credential specification",
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

	spec, err := c.Sys().GetCredentialSpec(name)
	if err != nil {
		return fmt.Errorf("error reading credential spec %s: %w", name, err)
	}

	headers := []string{"Key", "Value"}
	data := [][]any{
		{"Name", spec.Name},
		{"Type", spec.Type},
		{"Source", spec.SourceName},
		{"Min TTL", spec.MinTTL},
		{"Max TTL", spec.MaxTTL},
	}

	if spec.TargetName != "" {
		data = append(data, []any{"Target", spec.TargetName})
	}

	if len(spec.SourceParams) > 0 {
		data = append(data, []any{"Source Params", ""})
		for key, value := range spec.SourceParams {
			data = append(data, []any{fmt.Sprintf("  %s", key), value})
		}
	}

	helpers.PrintTable(headers, data)
	return nil
}
