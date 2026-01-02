package auth

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
		Short:         "This command disables an auth method.",
		Long: `
Usage: warden auth disable PATH

  Disables an auth method at the given PATH. The argument corresponds to
  the enabled PATH of the auth method.

  Disable the auth method enabled at jwt/:

      $ warden auth disable jwt/
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

	// Disable the auth method
	err = c.Sys().DisableAuth(path)
	if err != nil {
		return fmt.Errorf("error disabling auth method at path %s: %w", path, err)
	}

	fmt.Printf("Success! Disabled auth method at: %s\n", path)
	return nil
}
