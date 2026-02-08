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

  IMPORTANT: Warden operates in fail-closed mode - at least one audit
  device must always be enabled. Attempting to disable the last audit
  device will be rejected.

  List all enabled audit devices:

      $ warden audit list

  Enable a new audit device:

      $ warden audit enable --type=file --file-path=/var/log/warden-audit.log

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
