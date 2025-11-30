package providers

import "github.com/spf13/cobra"


var (
	DisableCmd = &cobra.Command{
		Use:   "disable",
		Short: "This command disable a provider.",
		Long: `
Usage: warden providers disable --path=PATH

  Disables a provider at the given PATH. The option corresponds to
  the enabled PATH of the provider. 

  Disable the provider enabled at aws/:

      $ warden providers disable --path=aws/
`,
	}
)