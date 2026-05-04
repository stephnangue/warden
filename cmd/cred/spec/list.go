package spec

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var ListCmd = &cobra.Command{
	Use:           "list",
	Short:         "List all credential specifications",
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE:          runList,
}

func runList(cmd *cobra.Command, args []string) error {
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	specs, err := c.Sys().ListCredentialSpecs()
	if err != nil {
		return fmt.Errorf("error listing credential specs: %w", err)
	}

	if len(specs) == 0 {
		return helpers.RenderList(nil, func() {
			fmt.Println("No credential specs found.")
		})
	}

	items := make([]map[string]any, 0, len(specs))
	for _, s := range specs {
		item := map[string]any{
			"name":    s.Name,
			"type":    s.Type,
			"source":  s.Source,
			"min_ttl": s.MinTTL,
			"max_ttl": s.MaxTTL,
		}
		if s.RotationPeriod > 0 {
			item["rotation_period"] = s.RotationPeriod.String()
		}
		items = append(items, item)
	}

	return helpers.RenderList(items, func() {
		headers := []string{"Name", "Type", "Source", "Min TTL", "Max TTL", "Rotation Period"}
		data := make([][]any, 0, len(specs))
		for _, s := range specs {
			rotationPeriod := any("disabled")
			if s.RotationPeriod > 0 {
				rotationPeriod = s.RotationPeriod
			}
			data = append(data, []any{s.Name, s.Type, s.Source, s.MinTTL, s.MaxTTL, rotationPeriod})
		}
		helpers.PrintTable(headers, data)
	})
}
