package audit

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	DisableCmd = &cobra.Command{
		Use:           "disable PATH",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "This command disables an audit device.",
		Long: `
Usage: warden audit disable PATH

  Disables an audit device at the given PATH. The argument corresponds to
  the enabled PATH of the audit device.

  WARNING: Warden operates in fail-closed mode. You cannot disable the last
  remaining audit device. Attempting to do so will result in an error.

  WARNING: Once an audit device is disabled, its HMAC salt is lost. You will
  no longer be able to correlate entries in historical audit logs. Even if
  you re-enable an audit device at the same path, a new salt will be created.

  Disable the audit device enabled at file/:

      $ warden audit disable file/
`,
		Args: cobra.ExactArgs(1),
		RunE: runDisable,
	}
)

func runDisable(cmd *cobra.Command, args []string) error {
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	path := args[0]

	// Disable the audit device
	err = c.Sys().DisableAudit(path)
	if err != nil {
		return fmt.Errorf("error disabling audit device at path %s: %w", path, err)
	}

	fmt.Printf("Success! Disabled audit device at: %s\n", path)
	return nil
}
