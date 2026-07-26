package oidcissuer

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	ReadCmd = &cobra.Command{
		Use:           "read",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Show the OIDC issuer configuration and readiness",
		Long: `
Usage: warden oidc-issuer read

  Show the current OIDC issuer configuration — enabled state, issuer URL,
  assertion TTL, signing-key rotation timings, publisher (secrets masked), and
  whether the issuer is ready to mint. Root namespace only.

      $ warden oidc-issuer read
`,
		Args: cobra.NoArgs,
		RunE: runRead,
	}
)

func runRead(cmd *cobra.Command, args []string) error {
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	resource, err := c.Operator().Read(oidcIssuerConfigPath)
	if err != nil {
		return fmt.Errorf("error reading OIDC issuer configuration: %w", err)
	}
	if resource == nil || resource.Data == nil {
		fmt.Fprintln(os.Stderr, "No OIDC issuer configuration found.")
		return nil
	}

	return helpers.RenderMap(resource.Data, func() {
		helpers.PrintMapAsTable(resource.Data)
	})
}
