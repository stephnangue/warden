package source

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	createType           string
	createConfig         map[string]string
	createRotationPeriod string

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
	CreateCmd.Flags().StringVar(&createRotationPeriod, "rotation-period", "", "Rotation period for credential source (e.g., 24h, 30m) (required)")

	CreateCmd.MarkFlagRequired("type")
	CreateCmd.MarkFlagRequired("rotation-period")
}

func runCreate(cmd *cobra.Command, args []string) error {
	name := args[0]

	c, err := helpers.Client()
	if err != nil {
		return err
	}

	resolvedConfig, err := helpers.ResolveFileRefs(createConfig)
	if err != nil {
		return err
	}

	input := &api.CreateCredentialSourceInput{
		Type:   createType,
		Config: resolvedConfig,
	}

	if createRotationPeriod != "" {
		period, err := time.ParseDuration(createRotationPeriod)
		if err != nil {
			return fmt.Errorf("invalid rotation-period format: %w", err)
		}
		input.RotationPeriod = period
	}

	output, err := c.Sys().CreateCredentialSource(name, input)
	if err != nil {
		return fmt.Errorf("error creating credential source: %w", err)
	}

	fmt.Printf("Success! Created credential source: %s\n", output.Name)
	fmt.Printf("  Type: %s\n", output.Type)
	if output.RotationPeriod > 0 {
		fmt.Printf("  Rotation Period: %s\n", output.RotationPeriod)
	}

	if len(output.Config) > 0 {
		fmt.Println("  Configuration:")
		for key, value := range output.Config {
			// Server already masks sensitive values
			fmt.Printf("    %s: %s\n", key, value)
		}
	}

	return nil
}
