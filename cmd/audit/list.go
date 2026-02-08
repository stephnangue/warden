package audit

import (
	"fmt"
	"sort"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	ListCmd = &cobra.Command{
		Use:           "list",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Lists the enabled audit devices on the Warden server",
		Long: `
Usage: warden audit list

  Lists the enabled audit devices on the Warden server. This command also
  outputs information about the enabled path including type, accessor,
  and human-friendly descriptions.

  List all enabled audit devices:

      $ warden audit list
`,
		RunE: runList,
	}
)

func runList(cmd *cobra.Command, args []string) error {
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	// List all audit devices
	audits, err := c.Sys().ListAudit()
	if err != nil {
		return fmt.Errorf("error listing audit devices: %w", err)
	}

	if len(audits) == 0 {
		fmt.Println("No audit devices enabled")
		return nil
	}

	// Sort paths for consistent output
	paths := make([]string, 0, len(audits))
	for path := range audits {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	// Prepare data for table
	headers := []string{"Path", "Type", "Accessor", "Description"}
	var data [][]any

	for _, path := range paths {
		audit := audits[path]
		data = append(data, []any{
			path,
			audit.Type,
			audit.Accessor,
			audit.Description,
		})
	}

	helpers.PrintTable(headers, data)
	return nil
}
