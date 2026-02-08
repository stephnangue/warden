package audit

import (
	"fmt"
	"sort"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	ReadCmd = &cobra.Command{
		Use:           "read PATH",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Show information on an audit device",
		Long: `
Usage: warden audit read PATH

  Show information on an audit device enabled on the provided PATH.

  Read the audit device enabled at file/:

      $ warden audit read file/
`,
		Args: cobra.ExactArgs(1),
		RunE: runRead,
	}
)

func runRead(cmd *cobra.Command, args []string) error {
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	path := args[0]

	// Get audit device info for the specified path
	auditInfo, err := c.Sys().AuditInfo(path)
	if err != nil {
		return fmt.Errorf("error reading audit device at path %s: %w", path, err)
	}

	// Display audit device information
	headers := []string{"Key", "Value"}
	data := [][]any{
		{"path", path},
		{"type", auditInfo.Type},
		{"accessor", auditInfo.Accessor},
		{"description", auditInfo.Description},
	}

	// Add config entries if present (sorted for consistent output)
	if len(auditInfo.Config) > 0 {
		keys := make([]string, 0, len(auditInfo.Config))
		for key := range auditInfo.Config {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		for _, key := range keys {
			data = append(data, []any{fmt.Sprintf("config.%s", key), auditInfo.Config[key]})
		}
	}

	helpers.PrintTable(headers, data)
	return nil
}
