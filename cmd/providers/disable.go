package providers

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	DisableCmd = &cobra.Command{
		Use:           "disable PATH",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "This command disable a provider.",
		Long: `
Usage: warden provider disable PATH

  Disables a provider at the given PATH. The argument corresponds to
  the enabled PATH of the provider.

  Disable the provider enabled at aws/:

      $ warden provider disable aws/
`,
		Args: cobra.ExactArgs(1),
		RunE: runDisable,
	}
)

func runDisable(cmd *cobra.Command, args []string) error {
	// Create the client
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	path := args[0]

	// Unmount the provider
	err = c.Sys().Unmount(path)
	if err != nil {
		return fmt.Errorf("error disabling provider at path %s: %w", path, err)
	}

	fmt.Printf("Success! Disabled provider at: %s\n", path)
	return nil
}