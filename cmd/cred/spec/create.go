package spec

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	createType         string
	createSourceName   string
	createSourceParams map[string]string
	createMinTTL       string
	createMaxTTL       string
	createTargetName   string

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
	CreateCmd.Flags().StringVar(&createSourceName, "source", "", "Source name (required)")
	CreateCmd.Flags().StringToStringVar(&createSourceParams, "params", nil, "Source parameters (key=value)")
	CreateCmd.Flags().StringVar(&createMinTTL, "min-ttl", "1h", "Minimum TTL")
	CreateCmd.Flags().StringVar(&createMaxTTL, "max-ttl", "24h", "Maximum TTL")
	CreateCmd.Flags().StringVar(&createTargetName, "target", "", "Target name for routing")

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
		Type:         createType,
		SourceName:   createSourceName,
		SourceParams: createSourceParams,
		MinTTL:       minTTL,
		MaxTTL:       maxTTL,
		TargetName:   createTargetName,
	}

	output, err := c.Sys().CreateCredentialSpec(name, input)
	if err != nil {
		return fmt.Errorf("error creating credential spec: %w", err)
	}

	fmt.Printf("Success! Created credential spec: %s\n", output.Name)
	fmt.Printf("  Type: %s\n", output.Type)
	fmt.Printf("  Source: %s\n", output.SourceName)
	fmt.Printf("  Min TTL: %s\n", output.MinTTL)
	fmt.Printf("  Max TTL: %s\n", output.MaxTTL)

	return nil
}
