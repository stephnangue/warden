package audit

import "github.com/spf13/cobra"

var (
	AuditCmd = &cobra.Command{
		Use:   "audit",
		Short: "This command groups subcommands for managing Warden's audit devices.",
		Long: `
Usage: warden audit <subcommand> [options]

  This command groups subcommands for managing Warden's audit devices.
  Audit devices are responsible for logging all requests and responses
  for security compliance and forensics.

  IMPORTANT: Once any audit device is registered, Warden runs fail-closed -
  every request must be successfully audited or it is rejected. Disabling the
  last device is allowed and drops the server to an unaudited state until one
  is re-enabled, so re-enable promptly. Devices declared in HCL config cannot
  be disabled here.

  List all enabled audit devices:

      $ warden audit list

  Enable a new audit device:

      $ warden audit enable file -file-path=/var/log/warden-audit.log

  Read audit device details:

      $ warden audit read file/

  Disable an audit device:

      $ warden audit disable file/

  Please see the individual subcommand help for detailed usage information.
`,
	}
)

func init() {
	AuditCmd.AddCommand(EnableCmd)
	AuditCmd.AddCommand(DisableCmd)
	AuditCmd.AddCommand(ListCmd)
	AuditCmd.AddCommand(ReadCmd)
}
