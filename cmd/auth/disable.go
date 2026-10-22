package auth

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	disablePath string

	DisableCmd = &cobra.Command{
		Use:           "disable [PATH]",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "This command disables an auth method.",
		Long: `
Usage: warden auth disable [PATH]

  Disables an auth method at the given PATH. The PATH may be supplied
  either positionally or via -path (pick one — combining both is rejected).

  Disable the auth method enabled at jwt/:

      $ warden auth disable jwt/
      $ warden auth disable -path=jwt/
`,
		Args: cobra.MaximumNArgs(1),
		RunE: runDisable,
	}
)

func init() {
	DisableCmd.Flags().StringVar(&disablePath, "path", "", "Mount path (alternative to the positional PATH argument)")
}

func runDisable(cmd *cobra.Command, args []string) error {
	path, err := helpers.RequirePath(args, disablePath)
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

	if helpers.ResolveDryRun() {
		return helpers.DryRun(c, "DELETE", "sys/auth/{path}", nil)
	}

	// Disable the auth method. Its warnings name groups whose rules still list
	// the mount: they go to stderr and stay in the structured output.
	warnings, err := c.Sys().DisableAuthWithWarnings(context.Background(), path)
	if err != nil {
		return fmt.Errorf("error disabling auth method at path %s: %w", path, err)
	}
	helpers.PrintWarnings(warnings)

	data := map[string]any{"path": path, "disabled": true}
	if len(warnings) > 0 {
		data["warnings"] = warnings
	}
	return helpers.RenderMap(data, func() {
		fmt.Printf("Success! Disabled auth method at: %s\n", path)
	})
}
