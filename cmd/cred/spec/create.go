package spec

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	createType   string
	createSource string
	createConfig map[string]string
	createMinTTL string
	createMaxTTL string

	CreateCmd = &cobra.Command{
		Use:           "create <name>",
		Short:         "Create a new credential specification",
		Long:          `Creates a new credential specification with the given parameters.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.ExactArgs(1),
		RunE:          runCreate,
	}
)

func init() {
	CreateCmd.Flags().StringVar(&createType, "type", "", "Credential type (required)")
	CreateCmd.Flags().StringVar(&createSource, "source", "", "Source name (required)")
	CreateCmd.Flags().StringToStringVar(&createConfig, "config", nil, "Type-specific configuration (key=value)")
	CreateCmd.Flags().StringVar(&createMinTTL, "min-ttl", "1h", "Minimum TTL")
	CreateCmd.Flags().StringVar(&createMaxTTL, "max-ttl", "24h", "Maximum TTL")

	CreateCmd.MarkFlagRequired("type")
	CreateCmd.MarkFlagRequired("source")
}

func runCreate(cmd *cobra.Command, args []string) error {
	name := args[0]

	c, err := helpers.Client()
	if err != nil {
		return err
	}

	// Parse TTL durations
	minTTL, err := time.ParseDuration(createMinTTL)
	if err != nil {
		return fmt.Errorf("invalid min-ttl: %w", err)
	}

	maxTTL, err := time.ParseDuration(createMaxTTL)
	if err != nil {
		return fmt.Errorf("invalid max-ttl: %w", err)
	}

	input := &api.CreateCredentialSpecInput{
		Type:   createType,
		Source: createSource,
		Config: createConfig,
		MinTTL: minTTL,
		MaxTTL: maxTTL,
	}

	output, err := c.Sys().CreateCredentialSpec(name, input)
	if err != nil {
		return fmt.Errorf("error creating credential spec: %w", err)
	}

	fmt.Printf("Success! Created credential spec: %s\n", output.Name)
	fmt.Printf("  Type: %s\n", output.Type)
	fmt.Printf("  Source: %s\n", output.Source)
	fmt.Printf("  Min TTL: %s\n", output.MinTTL)
	fmt.Printf("  Max TTL: %s\n", output.MaxTTL)

	return nil
}
