package providers

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	disablePath string

	DisableCmd = &cobra.Command{
		Use:           "disable [PATH]",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "This command disable a provider.",
		Long: `
Usage: warden provider disable [PATH]

  Disables a provider at the given PATH. The PATH may be supplied either
  positionally or via --path (pick one — combining both is rejected).

  Disable the provider enabled at aws/:

      $ warden provider disable aws/
      $ warden provider disable --path=aws/
`,
		Args: cobra.MaximumNArgs(1),
		RunE: runDisable,
	}
)

func init() {
	DisableCmd.Flags().StringVar(&disablePath, "path", "", "Mount path (alternative to the positional PATH argument)")
}

func runDisable(cmd *cobra.Command, args []string) error {
	path, err := helpers.RequirePath(args, disablePath)
	if err != nil {
		return err
	}
	if err := helpers.ValidatePath(path); err != nil {
		return err
	}

	c, err := helpers.Client()
	if err != nil {
		return err
	}

	if helpers.ResolveDryRun() {
		return helpers.DryRun(c, "DELETE", "sys/providers/{path}", nil)
	}

	// Unmount the provider
	err = c.Sys().Unmount(path)
	if err != nil {
		return fmt.Errorf("error disabling provider at path %s: %w", path, err)
	}

	return helpers.RenderMap(map[string]any{"path": path, "disabled": true}, func() {
		fmt.Printf("Success! Disabled provider at: %s\n", path)
	})
}
