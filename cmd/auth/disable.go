package auth

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	disablePath  string
	disableForce bool

	DisableCmd = &cobra.Command{
		Use:           "disable [PATH]",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "This command disables an auth method.",
		Long: `
Usage: warden auth disable [PATH]

  Disables an auth method at the given PATH. The PATH may be supplied
  either positionally or via -path (pick one — combining both is rejected).

  A mount on which entities claim native identities is refused: a mount
  enabled again is a new mount, and the claims would be left on this one.
  Release or move them first ('warden identity alias'), or pass -force;
  the claims are then orphaned, and listed by
  'warden identity entity list -orphaned'. The entities claiming on a
  mount:

      $ warden identity entity list -o json \
          | jq -r '.[] | select(any(.aliases[]; .mount == "auth/jwt/")) | .name'

  Disable the auth method enabled at jwt/:

      $ warden auth disable jwt/
      $ warden auth disable -path=jwt/
      $ warden auth disable jwt/ -force
`,
		Args: cobra.MaximumNArgs(1),
		RunE: runDisable,
	}
)

func init() {
	DisableCmd.Flags().StringVar(&disablePath, "path", "", "Mount path (alternative to the positional PATH argument)")
	DisableCmd.Flags().BoolVar(&disableForce, "force", false,
		"Disable even while native identities are claimed on the mount (their claims are orphaned)")
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
	warnings, err := c.Sys().DisableAuthWithOptions(context.Background(), path, &api.DisableAuthOptions{Force: disableForce})
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
