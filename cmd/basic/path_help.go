package basic

import (
	"fmt"
	"strings"

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
  to a backend mount (e.g., "aws/"), returns the backend's overall help
  including gateway behavior, request format, and configuration options.
  If it points to a specific path (e.g., "aws/config"), returns help for
  that path.

  Output honors the global -output flag: in TTY/table mode the help text
  is printed verbatim, in JSON/NDJSON/text the response is returned as
  {"help": "..."} so agents can pipe it into jq.

  Examples:

    Read backend-level help for the AWS provider:

      $ warden path-help aws/

    Show help for the AWS config endpoint:

      $ warden path-help aws/config

    Show help for the JWT auth config:

      $ warden path-help auth/jwt/config

    Get a JSON envelope for agent consumption:

      $ warden path-help aws/ -o json
`,
	Args: cobra.ExactArgs(1),
	RunE: runPathHelp,
}

func runPathHelp(cmd *cobra.Command, args []string) error {
	// Trim leading slash for tolerance; preserve trailing slash because the
	// server treats "aws/" (backend root) and "aws/config" (specific path)
	// differently.
	path := strings.TrimPrefix(args[0], "/")
	if err := helpers.ValidatePath(path); err != nil {
		return err
	}

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
		return fmt.Errorf("no help available at path %q: %w", path, helpers.ErrNotFound)
	}

	help, _ := resource.Data["help"].(string)
	if help == "" {
		return fmt.Errorf("no help text found at path %q: %w", path, helpers.ErrNotFound)
	}

	return helpers.RenderMap(map[string]any{"help": help}, func() {
		fmt.Print(help)
		if !strings.HasSuffix(help, "\n") {
			fmt.Println()
		}
	})
}
