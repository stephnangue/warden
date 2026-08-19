package protectedresource

import "github.com/spf13/cobra"

// protectedResourceConfigPath is the API path of the global configuration.
const protectedResourceConfigPath = "sys/protected-resource/config"

var (
	ProtectedResourceCmd = &cobra.Command{
		Use:           "protected-resource",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Configure RFC 9728 protected resource metadata",
		Long: `
Usage: warden protected-resource <subcommand> [options]

  Warden publishes, for each opted-in mount, a metadata document naming the
  authorization server a client should obtain a USER credential from. A client
  that receives a 401 fetches the document, runs OAuth against that provider,
  and retries with the user's token on the Authorization header.

  Warden is a resource server only. It never issues user credentials and never
  serves authorization-server metadata.

  A mount opts in by setting user_auth_path in its own configuration. This
  command configures the deployment-wide parts: the external base URL clients
  reach Warden at, and optional overrides. Root namespace only.

      $ warden protected-resource configure -resource-url=https://warden.example.com
      $ warden protected-resource read
      $ warden protected-resource disable

  Documents are then served at:

      /.well-known/oauth-protected-resource/v1/<namespace>/<mount>
`,
	}
)

func init() {
	ProtectedResourceCmd.AddCommand(ConfigureCmd)
	ProtectedResourceCmd.AddCommand(ReadCmd)
	ProtectedResourceCmd.AddCommand(DisableCmd)
}
