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
	if err := helpers.ValidatePath(name); err != nil {
		return err
	}

	c, err := helpers.Client()
	if err != nil {
		return err
	}

	sp, err := c.Sys().GetCredentialSpec(name)
	if err != nil {
		return fmt.Errorf("error reading credential spec %s: %w", name, err)
	}

	data := map[string]any{
		"name":    sp.Name,
		"type":    sp.Type,
		"source":  sp.Source,
		"min_ttl": sp.MinTTL,
		"max_ttl": sp.MaxTTL,
	}
	if sp.RotationPeriod > 0 {
		data["rotation_period"] = sp.RotationPeriod.String()
	}
	if len(sp.Config) > 0 {
		cfg := make(map[string]any, len(sp.Config))
		for k, v := range sp.Config {
			cfg[k] = v
		}
		data["config"] = cfg
	}

	return helpers.RenderMap(data, func() {
		headers := []string{"Key", "Value"}
		rows := [][]any{
			{"Name", sp.Name},
			{"Type", sp.Type},
			{"Source", sp.Source},
			{"Min TTL", sp.MinTTL},
			{"Max TTL", sp.MaxTTL},
		}
		if sp.RotationPeriod > 0 {
			rows = append(rows, []any{"Rotation Period", sp.RotationPeriod})
		} else {
			rows = append(rows, []any{"Rotation Period", "disabled"})
		}
		if len(sp.Config) > 0 {
			rows = append(rows, []any{"Config", ""})
			keys := make([]string, 0, len(sp.Config))
			for k := range sp.Config {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				rows = append(rows, []any{fmt.Sprintf("  %s", k), sp.Config[k]})
			}
		}
		helpers.PrintTable(headers, rows)
	})
}
