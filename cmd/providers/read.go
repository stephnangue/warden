package providers

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
	Short:         "Show information on a provider",
	Long: `
Usage: warden provider read PATH

  Show information on a provider enabled on the provided PATH.

  Read the provider enabled at aws/:

      $ warden provider read aws/
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
	if err := helpers.ValidatePath(path); err != nil {
		return err
	}

	mountInfo, err := c.Sys().MountInfo(path)
	if err != nil {
		return fmt.Errorf("error reading provider at path %s: %w", path, err)
	}

	data := map[string]any{
		"path":        path,
		"type":        mountInfo.Type,
		"accessor":    mountInfo.Accessor,
		"description": mountInfo.Description,
		"mount_url":   mountInfo.MountURL,
	}
	if len(mountInfo.Config) > 0 {
		cfg := make(map[string]any, len(mountInfo.Config))
		for k, v := range mountInfo.Config {
			cfg[k] = v
		}
		data["config"] = cfg
	}

	return helpers.RenderMap(data, func() {
		headers := []string{"Key", "Value"}
		rows := [][]any{
			{"path", path},
			{"type", mountInfo.Type},
			{"accessor", mountInfo.Accessor},
			{"description", mountInfo.Description},
		}
		if len(mountInfo.Config) > 0 {
			keys := make([]string, 0, len(mountInfo.Config))
			for k := range mountInfo.Config {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				rows = append(rows, []any{k, mountInfo.Config[k]})
			}
		}
		helpers.PrintTable(headers, rows)
	})
}
