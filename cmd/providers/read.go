package providers

import "github.com/spf13/cobra"

var (
	ReadCmd = &cobra.Command{
		Use:   "read",
		Short: "Show information on a provider",
		Long: `
Usage: warden providers read --path=PATH

  Show information on a provider enabled on the provided PATH. 

  Read the provider enabled at aws/:

      $ warden providers read --path=aws/
`,
	}
)