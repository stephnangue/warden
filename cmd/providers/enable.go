package providers

import "github.com/spf13/cobra"

var (
	EnableCmd = &cobra.Command{
		Use:   "enable",
		Short: "This command enable a provider.",
		Long: `
Usage: warden providers enable [options]

  Enables a provider. By default, providers are enabled at the path
  corresponding to their TYPE, but users can customize the path using the
  --path option.

  Once enabled, Warden will route all requests which begin with the path to the
  provider.

  Enable the AWS provider at aws/:

      $ warden provider enable --type=aws

  Enable the Azure provider at azure-prod/:

      $ warden providers enable --type=azure --path=azure-prod

  Enable the aws provider with proxy domains:

      $ warden providers enable --type=aws --proxy_domains=localhost,warden

  For a full list of providers and examples, please see the documentation.
`,
	}
)