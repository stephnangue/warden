package basic

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var PathHelpCmd = &cobra.Command{
	Use:           "path-help",
	SilenceUsage:  true,
	SilenceErrors: true,
	Short:         "Display help for a path or backend",
	Long: `
Usage: warden path-help PATH

  Display provider-specific help for the given path. If the path points
  to a backend mount (e.g., "aws/"), lists all available paths. If it
  points to a specific path (e.g., "aws/config"), shows detailed help
  including parameters and description.

  Examples:

    List all paths for the AWS provider:

      $ warden path-help aws/

    Show help for the AWS config endpoint:

      $ warden path-help aws/config

    Show help for the Vault gateway endpoint:

      $ warden path-help vault/gateway

    Show help for the JWT auth config:

      $ warden path-help auth/jwt/config
`,
	Args: cobra.ExactArgs(1),
	RunE: runPathHelp,
}

func runPathHelp(cmd *cobra.Command, args []string) error {
	path := args[0]

	c, err := helpers.Client()
	if err != nil {
		return err
	}

	resource, err := c.Operator().ReadWithData(path, map[string][]string{
		"warden-help": {"1"},
	})
	if err != nil {
		return fmt.Errorf("failed to get help for %s: %w", path, err)
	}

	if resource == nil || resource.Data == nil {
		fmt.Fprintf(os.Stderr, "No help available at path: %s\n", path)
		return nil
	}

	if help, ok := resource.Data["help"].(string); ok {
		fmt.Print(help)
	} else {
		fmt.Fprintf(os.Stderr, "No help text found at path: %s\n", path)
	}

	return nil
}
