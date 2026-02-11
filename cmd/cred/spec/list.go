package spec

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	listFormat string

	ListCmd = &cobra.Command{
		Use:           "list",
		Short:         "List all credential specifications",
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

	specs, err := c.Sys().ListCredentialSpecs()
	if err != nil {
		return fmt.Errorf("error listing credential specs: %w", err)
	}

	if len(specs) == 0 {
		fmt.Println("No credential specs found.")
		return nil
	}

	headers := []string{"Name", "Type", "Source", "Min TTL", "Max TTL", "Rotation Period"}
	data := make([][]any, 0, len(specs))

	for _, spec := range specs {
		rotationPeriod := any("disabled")
		if spec.RotationPeriod > 0 {
			rotationPeriod = spec.RotationPeriod
		}
		data = append(data, []any{
			spec.Name,
			spec.Type,
			spec.Source,
			spec.MinTTL,
			spec.MaxTTL,
			rotationPeriod,
		})
	}

	helpers.PrintTable(headers, data)
	return nil
}
