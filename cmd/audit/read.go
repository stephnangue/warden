package audit

import (
	"fmt"
	"sort"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	readPath string

	ReadCmd = &cobra.Command{
		Use:           "read [PATH]",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Show information on an audit device",
		Long: `
Usage: warden audit read [PATH]

  Show information on an audit device enabled on the provided PATH. The
  PATH may be supplied either positionally or via -path (pick one —
  combining both is rejected).

  Read the audit device enabled at file/:

      $ warden audit read file/
      $ warden audit read -path=file/
`,
		Args: cobra.MaximumNArgs(1),
		RunE: runRead,
	}
)

func init() {
	ReadCmd.Flags().StringVar(&readPath, "path", "", "Mount path (alternative to the positional PATH argument)")
}

func runRead(cmd *cobra.Command, args []string) error {
	path, err := helpers.RequirePath(args, readPath)
	if err != nil {
		return err
	}
	if err := helpers.ValidatePath(path); err != nil {
		return err
	}

	c, err := helpers.Client()
	if err != nil {
		return err
	}

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
