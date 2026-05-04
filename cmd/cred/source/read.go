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

	src, err := c.Sys().GetCredentialSource(name)
	if err != nil {
		return fmt.Errorf("error reading credential source %s: %w", name, err)
	}

	data := map[string]any{
		"name": src.Name,
		"type": src.Type,
	}
	if src.RotationPeriod > 0 {
		data["rotation_period"] = src.RotationPeriod.String()
	}
	if src.NextRotation != "" {
		data["next_rotation"] = src.NextRotation
	}
	if src.LastRotation != "" {
		data["last_rotation"] = src.LastRotation
	}
	if len(src.Config) > 0 {
		cfg := make(map[string]any, len(src.Config))
		for k, v := range src.Config {
			cfg[k] = v
		}
		data["config"] = cfg
	}

	return helpers.RenderMap(data, func() {
		headers := []string{"Key", "Value"}
		rows := [][]any{
			{"Name", src.Name},
			{"Type", src.Type},
		}
		if src.RotationPeriod > 0 {
			rows = append(rows, []any{"Rotation Period", src.RotationPeriod.String()})
		}
		if src.NextRotation != "" {
			rows = append(rows, []any{"Next Rotation", src.NextRotation})
		}
		if src.LastRotation != "" {
			rows = append(rows, []any{"Last Rotation", src.LastRotation})
		}
		if len(src.Config) > 0 {
			rows = append(rows, []any{"Configuration", ""})
			keys := make([]string, 0, len(src.Config))
			for k := range src.Config {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				rows = append(rows, []any{fmt.Sprintf("  %s", k), src.Config[k]})
			}
		}
		helpers.PrintTable(headers, rows)
	})
}
