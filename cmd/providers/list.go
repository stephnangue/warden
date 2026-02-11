package providers

import (
	"fmt"
	"sort"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	ListCmd = &cobra.Command{
		Use:   "list",
    	SilenceUsage:  true,
		SilenceErrors: true,
		Short: "Lists the enabled providers on the Warden server",
		Long: `
Usage: warden provider list

  Lists the enabled providers on the Warden server. This command also
  outputs information about the enabled path including a
  human-friendly descriptions.

  List all enabled providers:

      $ warden provider list
`,
		RunE: runList,
	}
)

func runList(cmd *cobra.Command, args []string) error {
	// Create the client
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	// List all mounts/providers
	mounts, err := c.Sys().ListMounts()
	if err != nil {
		return fmt.Errorf("error listing providers: %w", err)
	}

	if len(mounts) == 0 {
		fmt.Println("No providers enabled")
		return nil
	}

	// Prepare data for table
	headers := []string{"Path", "Type", "Accessor", "Description"}
	var data [][]any

	// Sort paths for consistent output
	paths := make([]string, 0, len(mounts))
	for path := range mounts {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	for _, path := range paths {
		mount := mounts[path]
		data = append(data, []any{
			path,
			mount.Type,
			mount.Accessor,
			mount.Description,
		})
	}

	helpers.PrintTable(headers, data)
	return nil
}