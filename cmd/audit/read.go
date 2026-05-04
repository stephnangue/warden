package audit

import (
	"fmt"
	"sort"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var ReadCmd = &cobra.Command{
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

func runRead(cmd *cobra.Command, args []string) error {
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	path := args[0]

	auditInfo, err := c.Sys().AuditInfo(path)
	if err != nil {
		return fmt.Errorf("error reading audit device at path %s: %w", path, err)
	}

	data := map[string]any{
		"path":        path,
		"type":        auditInfo.Type,
		"accessor":    auditInfo.Accessor,
		"description": auditInfo.Description,
	}
	if len(auditInfo.Config) > 0 {
		cfg := make(map[string]any, len(auditInfo.Config))
		for k, v := range auditInfo.Config {
			cfg[k] = v
		}
		data["config"] = cfg
	}

	return helpers.RenderMap(data, func() {
		headers := []string{"Key", "Value"}
		rows := [][]any{
			{"path", path},
			{"type", auditInfo.Type},
			{"accessor", auditInfo.Accessor},
			{"description", auditInfo.Description},
		}
		if len(auditInfo.Config) > 0 {
			keys := make([]string, 0, len(auditInfo.Config))
			for k := range auditInfo.Config {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				rows = append(rows, []any{fmt.Sprintf("config.%s", k), auditInfo.Config[k]})
			}
		}
		helpers.PrintTable(headers, rows)
	})
}
