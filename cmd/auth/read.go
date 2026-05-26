package auth

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
		Short:         "Show information on an auth method",
		Long: `
Usage: warden auth read [PATH]

  Show information on an auth method enabled on the provided PATH. The
  PATH may be supplied either positionally or via -path (pick one —
  combining both is rejected).

  Read the auth method enabled at jwt/:

      $ warden auth read jwt/
      $ warden auth read -path=jwt/
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

	authInfo, err := c.Sys().AuthInfo(path)
	if err != nil {
		return fmt.Errorf("error reading auth method at path %s: %w", path, err)
	}

	data := map[string]any{
		"path":        path,
		"type":        authInfo.Type,
		"accessor":    authInfo.Accessor,
		"description": authInfo.Description,
	}
	if len(authInfo.Config) > 0 {
		cfg := make(map[string]any, len(authInfo.Config))
		for k, v := range authInfo.Config {
			cfg[k] = v
		}
		data["config"] = cfg
	}

	return helpers.RenderMap(data, func() {
		headers := []string{"Key", "Value"}
		rows := [][]any{
			{"path", path},
			{"type", authInfo.Type},
			{"accessor", authInfo.Accessor},
			{"description", authInfo.Description},
		}
		if len(authInfo.Config) > 0 {
			keys := make([]string, 0, len(authInfo.Config))
			for k := range authInfo.Config {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				rows = append(rows, []any{k, authInfo.Config[k]})
			}
		}
		helpers.PrintTable(headers, rows)
	})
}
