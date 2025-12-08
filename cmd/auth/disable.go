package auth

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	disablePath string

	DisableCmd = &cobra.Command{
		Use:   "disable",
    	SilenceUsage:  true,
		SilenceErrors: true,
		Short: "This command disables an auth method.",
		Long: `
Usage: warden auth disable --path=PATH

  Disables an auth method at the given PATH. The option corresponds to
  the enabled PATH of the auth method.

  Disable the auth method enabled at jwt/:

      $ warden auth disable --path=jwt/
`,
		RunE: runDisable,
	}
)

func init() {
	DisableCmd.Flags().StringVar(&disablePath, "path", "", "Path of the auth method to disable (required)")
	DisableCmd.MarkFlagRequired("path")
}

func runDisable(cmd *cobra.Command, args []string) error {
	// Create the client
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	// Disable the auth method
	err = c.Sys().DisableAuth(disablePath)
	if err != nil {
		return fmt.Errorf("error disabling auth method at path %s: %w", disablePath, err)
	}

	fmt.Printf("Success! Disabled auth method at: %s\n", disablePath)
	return nil
}
