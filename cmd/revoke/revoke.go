package revoke

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	RevokeRootTokenCmd = &cobra.Command{
		Use:           "revoke-root-token",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Revoke the current root token",
		Long: `
Revokes the current root token, invalidating it immediately.

After revocation, you must run 'warden init' to generate a new root token.

Usage:
  $ warden revoke-root-token

Note: This command requires authentication with the current root token.
Set the WARDEN_TOKEN environment variable with the root token before running.
`,
		RunE: run,
	}
)

func run(cmd *cobra.Command, args []string) error {
	// Create the client
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	// Call Revoke API
	if err := c.Sys().RevokeRootToken(); err != nil {
		return fmt.Errorf("revocation failed: %w", err)
	}

	fmt.Println()
	fmt.Println("Root token successfully revoked")
	fmt.Println("Run 'warden init' to generate a new root token")
	fmt.Println()

	return nil
}
