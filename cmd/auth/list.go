package auth

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
		Short: "Lists the enabled auth methods on the Warden server",
		Long: `
Usage: warden auth list

  Lists the enabled auth methods on the Warden server. This command also
  outputs information about the enabled path including a
  human-friendly descriptions.

  List all enabled auth methods:

      $ warden auth list
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

	// List all auth methods
	auths, err := c.Sys().ListAuth()
	if err != nil {
		return fmt.Errorf("error listing auth methods: %w", err)
	}

	if len(auths) == 0 {
		fmt.Println("No auth methods enabled")
		return nil
	}

	// Prepare data for table
	headers := []string{"Path", "Type", "Accessor", "Description"}
	var data [][]any

	// Sort paths for consistent output
	paths := make([]string, 0, len(auths))
	for path := range auths {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	for _, path := range paths {
		auth := auths[path]
		data = append(data, []any{
			path,
			auth.Type,
			auth.Accessor,
			auth.Description,
		})
	}

	helpers.PrintTable(headers, data)
	return nil
}
