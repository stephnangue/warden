package status

import (
	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var StatusCmd = &cobra.Command{
	Use:           "status",
	Args:          cobra.NoArgs,
	SilenceUsage:  true,
	SilenceErrors: true,
	Short:         "Show Warden server status",
	Long: `
Usage: warden status

  Prints initialization, seal, and HA/cluster state. Thin wrapper over
  /v1/sys/health.

  Exit codes (rough parity with vault status, mapped onto warden's scheme):
    0    initialized and unsealed (active or standby)
    7    transport / connection error
    10   sealed or uninitialized

Examples:

  $ warden status
  $ warden status -o json
  $ warden status -o json -fields sealed,is_leader,leader_address
`,
	RunE: runStatus,
}

func runStatus(cmd *cobra.Command, args []string) error {
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	h, err := c.Sys().HealthWithContext(cmd.Context())
	if err != nil {
		return err
	}

	data := map[string]any{
		"initialized": h.Initialized,
		"sealed":      h.Sealed,
		"standby":     h.Standby,
		"ha_enabled":  h.HAEnabled,
		"is_leader":   h.IsLeader,
		"server_time": h.ServerTime,
	}
	// leader_address and active_time are only meaningful when HA is on.
	// version is omitted from the table when the server didn't report one
	// (older server, or stripped binary).
	if h.HAEnabled {
		if h.LeaderAddress != "" {
			data["leader_address"] = h.LeaderAddress
		}
		if h.ActiveTime != "" {
			data["active_time"] = h.ActiveTime
		}
	}
	if h.Version != "" {
		data["version"] = h.Version
	}

	if err := helpers.RenderMap(data, nil); err != nil {
		return err
	}

	if h.Sealed || !h.Initialized {
		return helpers.ErrSealed
	}
	return nil
}
