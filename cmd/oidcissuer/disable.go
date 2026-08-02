package oidcissuer

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	DisableCmd = &cobra.Command{
		Use:           "disable",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Disable the OIDC issuer",
		Long: `
Usage: warden oidc-issuer disable

  Disable the OIDC issuer. The warden_identity mint path fails closed until it
  is re-enabled. The rest of the configuration (issuer URL, timings, publisher)
  is retained, so a later 'configure' can re-enable without re-supplying it.
  Root namespace only.

      $ warden oidc-issuer disable
`,
		Args: cobra.NoArgs,
		RunE: runDisable,
	}
)

func runDisable(cmd *cobra.Command, args []string) error {
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	payload := map[string]any{"enabled": false}

	if helpers.ResolveDryRun() {
		return helpers.DryRun(c, "POST", oidcIssuerConfigPath, payload)
	}

	if _, err := c.Operator().Write(oidcIssuerConfigPath, payload); err != nil {
		return fmt.Errorf("error disabling OIDC issuer: %w", err)
	}

	return helpers.RenderMap(map[string]any{"enabled": false}, func() {
		fmt.Println("Success! OIDC issuer disabled.")
	})
}
