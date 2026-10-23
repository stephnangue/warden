package basic

import (
	"fmt"
	"maps"
	"os"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	readPath string

	ReadCmd = &cobra.Command{
		Use:           "read",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Read data from a path",
		Long: `
Usage: warden read [PATH]

  Read data from the given path. The PATH may be supplied either
  positionally or via -path (pick one — combining both is rejected).
  The path should be in the format "provider_mount/resource" or
  "auth/auth_mount/resource" or "sys/path/to/resource" and will be
  converted to the appropriate API path.

  Examples:

    Read AWS provider configuration:

      $ warden read aws/config
      $ warden read -path=aws/config

    Read JWT auth configuration:

      $ warden read auth/jwt/config

    Read system mounts:

      $ warden read sys/mounts

    Project specific fields:

      $ warden read aws/config -fields proxy_domains,timeout
`,
		Args: cobra.MaximumNArgs(1),
		RunE: runRead,
	}
)

func init() {
	ReadCmd.Flags().StringVar(&readPath, "path", "", "API path (alternative to the positional PATH argument)")
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

	resource, err := c.Operator().Read(path)
	if err != nil {
		return fmt.Errorf("failed to read from %s: %w", path, err)
	}

	if resource == nil || resource.Data == nil {
		fmt.Fprintf(os.Stderr, "No data found at path: %s\n", path)
		return nil
	}

	// A response's warnings (a configuration read that names a removed
	// setting, an auth path naming a mount of the wrong kind) go to stderr.
	// They stay in the structured output; the table leaves them out, having
	// shown them already.
	warnings := helpers.WarningsFromData(resource.Data)
	helpers.PrintWarnings(warnings)

	return helpers.RenderMap(resource.Data, func() {
		table := resource.Data
		if len(warnings) > 0 {
			table = maps.Clone(resource.Data)
			delete(table, "warnings")
		}
		helpers.PrintMapAsTable(table)
	})
}
