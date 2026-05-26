package audit

import (
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
		Short:         "This command disables an audit device.",
		Long: `
Usage: warden audit disable [PATH]

  Disables an audit device at the given PATH. The PATH may be supplied
  either positionally or via -path (pick one — combining both is rejected).

  WARNING: Warden operates in fail-closed mode. You cannot disable the last
  remaining audit device. Attempting to do so will result in an error.

  WARNING: Once an audit device is disabled, its HMAC salt is lost. You will
  no longer be able to correlate entries in historical audit logs. Even if
  you re-enable an audit device at the same path, a new salt will be created.

  Disable the audit device enabled at file/:

      $ warden audit disable file/
      $ warden audit disable -path=file/
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
		return helpers.DryRun(c, "DELETE", "sys/audit/{path}", nil)
	}

	// Disable the audit device
	err = c.Sys().DisableAudit(path)
	if err != nil {
		return fmt.Errorf("error disabling audit device at path %s: %w", path, err)
	}

	return helpers.RenderMap(map[string]any{"path": path, "disabled": true}, func() {
		fmt.Printf("Success! Disabled audit device at: %s\n", path)
	})
}
