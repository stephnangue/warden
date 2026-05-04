package basic

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var ReadCmd = &cobra.Command{
	Use:           "read",
	SilenceUsage:  true,
	SilenceErrors: true,
	Short:         "Read data from a path",
	Long: `
Usage: warden read PATH

  Read data from the given path. The path should be in the format
  "provider_mount/resource" or "auth/auth_mount/resource" or "sys/path/to/resource"
  and will be converted to the appropriate API path.

  Examples:

    Read AWS provider configuration:

      $ warden read aws/config

    Read JWT auth configuration:

      $ warden read auth/jwt/config

    Read system mounts:

      $ warden read sys/mounts

    Project specific fields:

      $ warden read aws/config --fields proxy_domains,timeout
`,
	Args: cobra.ExactArgs(1),
	RunE: runRead,
}

func runRead(cmd *cobra.Command, args []string) error {
	path := args[0]

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

	return helpers.RenderMap(resource.Data, func() {
		helpers.PrintMapAsTable(resource.Data)
	})
}
