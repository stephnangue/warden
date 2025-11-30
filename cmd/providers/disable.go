package providers

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
		Short: "This command disable a provider.",
		Long: `
Usage: warden providers disable --path=PATH

  Disables a provider at the given PATH. The option corresponds to
  the enabled PATH of the provider.

  Disable the provider enabled at aws/:

      $ warden providers disable --path=aws/
`,
		RunE: runDisable,
	}
)

func init() {
	DisableCmd.Flags().StringVar(&disablePath, "path", "", "Path of the provider to disable (required)")
	DisableCmd.MarkFlagRequired("path")
}

func runDisable(cmd *cobra.Command, args []string) error {
	// Create the client
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	// Unmount the provider
	err = c.Sys().Unmount(disablePath)
	if err != nil {
		return fmt.Errorf("error disabling provider at path %s: %w", disablePath, err)
	}

	fmt.Printf("Success! Disabled provider at: %s\n", disablePath)
	return nil
}