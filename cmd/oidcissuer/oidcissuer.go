package oidcissuer

import "github.com/spf13/cobra"

// oidcIssuerConfigPath is the API path of the OIDC issuer's global configuration.
// The issuer is a single trust root shared by every namespace, so this path is
// readable/writable only in the root namespace (the server enforces it).
const oidcIssuerConfigPath = "sys/oidc-issuer/config"

var (
	OIDCIssuerCmd = &cobra.Command{
		Use:   "oidc-issuer",
		Short: "This command groups subcommands for configuring Warden's OIDC issuer.",
		Long: `
Usage: warden oidc-issuer <subcommand> [options]

  This command groups subcommands for configuring Warden as an OIDC issuer
  for Workload Identity Federation (WIF). When enabled, Warden mints short-lived
  identity assertions for calling agents and publishes the JWKS + discovery
  documents an upstream (AWS STS, an OAuth token endpoint, ...) federates.

  The issuer is a single GLOBAL trust root and can only be configured in the
  root namespace.

  Configure and enable the issuer:

      $ warden oidc-issuer configure -issuer-url=https://warden.example.com

  Show the current configuration and readiness:

      $ warden oidc-issuer read

  Disable the issuer:

      $ warden oidc-issuer disable

  Please see the individual subcommand help for detailed usage information.
`,
	}
)

func init() {
	OIDCIssuerCmd.AddCommand(ConfigureCmd)
	OIDCIssuerCmd.AddCommand(ReadCmd)
	OIDCIssuerCmd.AddCommand(DisableCmd)
}
