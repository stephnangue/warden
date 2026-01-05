package source

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	createType   string
	createConfig map[string]string

	CreateCmd = &cobra.Command{
		Use:           "create <name>",
		Short:         "Create a new credential source",
		Long:          `Creates a new credential source with the given configuration.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.ExactArgs(1),
		RunE:          runCreate,
	}
)

func init() {
	CreateCmd.Flags().StringVar(&createType, "type", "", "Source type (required)")
	CreateCmd.Flags().StringToStringVar(&createConfig, "config", nil, "Source configuration (key=value)")

	CreateCmd.MarkFlagRequired("type")
}

func runCreate(cmd *cobra.Command, args []string) error {
	name := args[0]

	c, err := helpers.Client()
	if err != nil {
		return err
	}

	input := &api.CreateCredentialSourceInput{
		Type:   createType,
		Config: createConfig,
	}

	output, err := c.Sys().CreateCredentialSource(name, input)
	if err != nil {
		return fmt.Errorf("error creating credential source: %w", err)
	}

	fmt.Printf("Success! Created credential source: %s\n", output.Name)
	fmt.Printf("  Type: %s\n", output.Type)

	if len(output.Config) > 0 {
		fmt.Println("  Configuration:")
		for key, value := range output.Config {
			// Mask sensitive values
			displayValue := value
			if key == "token" || key == "password" || key == "secret" {
				displayValue = "***"
			}
			fmt.Printf("    %s: %s\n", key, displayValue)
		}
	}

	return nil
}
