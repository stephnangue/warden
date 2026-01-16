package spec

import (
	"fmt"
	"sort"

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
		{"Source", spec.Source},
		{"Min TTL", spec.MinTTL},
		{"Max TTL", spec.MaxTTL},
	}

	if len(spec.Config) > 0 {
		data = append(data, []any{"Config", ""})
		// Sort config keys for consistent output
		keys := make([]string, 0, len(spec.Config))
		for key := range spec.Config {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			data = append(data, []any{fmt.Sprintf("  %s", key), spec.Config[key]})
		}
	}

	helpers.PrintTable(headers, data)
	return nil
}
