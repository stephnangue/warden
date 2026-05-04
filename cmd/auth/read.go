package auth

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
	Short:         "Show information on an auth method",
	Long: `
Usage: warden auth read PATH

  Show information on an auth method enabled on the provided PATH.

  Read the auth method enabled at jwt/:

      $ warden auth read jwt/
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
