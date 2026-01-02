package providers

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	enableType        string
	enableDescription string

	EnableCmd = &cobra.Command{
		Use:           "enable [PATH]",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "This command enable a provider.",
		Long: `
Usage: warden provider enable [options] [PATH]

  Enables a provider. By default, providers are enabled at the path
  corresponding to their TYPE, but users can customize the path by providing
  it as a positional argument.

  Once enabled, Warden will route all requests which begin with the path to the
  provider.

  Enable the AWS provider at aws/:

      $ warden provider enable --type=aws

  Enable the Azure provider at azure-prod/:

      $ warden provider enable --type=azure azure-prod

  For a full list of providers and examples, please see the documentation.
`,
		RunE: runEnable,
	}
)

func init() {
	EnableCmd.Flags().StringVar(&enableType, "type", "", "Type of the provider (e.g., aws, azure, gcp) (required)")
	EnableCmd.Flags().StringVar(&enableDescription, "description", "", "Human-friendly description of the provider")
	EnableCmd.MarkFlagRequired("type")
}

func runEnable(cmd *cobra.Command, args []string) error {
	// Create the client
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	// Determine path from positional argument or use type as default
	var path string
	if len(args) > 0 {
		path = args[0]
	} else {
		path = enableType + "/"
	}

	// Ensure path ends with /
	if !strings.HasSuffix(path, "/") {
		path = path + "/"
	}

	// Build mount input
	mountInput := &api.MountInput{
		Type:        enableType,
		Description: enableDescription,
	}

	// Mount the provider
	err = c.Sys().Mount(path, mountInput)
	if err != nil {
		return fmt.Errorf("error enabling provider: %w", err)
	}

	fmt.Printf("Success! Enabled %s provider at: %s\n", enableType, path)
	return nil
}