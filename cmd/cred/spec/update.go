package spec

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	updateConfig         map[string]string
	updateMinTTL         string
	updateMaxTTL         string
	updateRotationPeriod string

	UpdateCmd = &cobra.Command{
		Use:           "update <name>",
		Short:         "Update a credential specification",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.ExactArgs(1),
		RunE:          runUpdate,
	}
)

func init() {
	UpdateCmd.Flags().StringToStringVar(&updateConfig, "config", nil, "Type-specific configuration (key=value)")
	UpdateCmd.Flags().StringVar(&updateMinTTL, "min-ttl", "", "Minimum TTL")
	UpdateCmd.Flags().StringVar(&updateMaxTTL, "max-ttl", "", "Maximum TTL")
	UpdateCmd.Flags().StringVar(&updateRotationPeriod, "rotation-period", "", "Rotation period for credentials stored in the spec (e.g., '24h', '7d'). Use '0' to disable rotation")
}

func runUpdate(cmd *cobra.Command, args []string) error {
	name := args[0]

	// Require at least one update parameter
	if len(updateConfig) == 0 && updateMinTTL == "" && updateMaxTTL == "" && updateRotationPeriod == "" {
		return fmt.Errorf("no update parameters provided. Use --config, --min-ttl, --max-ttl, or --rotation-period")
	}

	c, err := helpers.Client()
	if err != nil {
		return err
	}

	input := &api.UpdateCredentialSpecInput{
		Config: updateConfig,
	}

	if updateMinTTL != "" {
		minTTL, err := time.ParseDuration(updateMinTTL)
		if err != nil {
			return fmt.Errorf("invalid min-ttl: %w", err)
		}
		input.MinTTL = &minTTL
	}

	if updateMaxTTL != "" {
		maxTTL, err := time.ParseDuration(updateMaxTTL)
		if err != nil {
			return fmt.Errorf("invalid max-ttl: %w", err)
		}
		input.MaxTTL = &maxTTL
	}

	if updateRotationPeriod != "" {
		rotationPeriod, err := time.ParseDuration(updateRotationPeriod)
		if err != nil {
			return fmt.Errorf("invalid rotation-period: %w", err)
		}
		input.RotationPeriod = &rotationPeriod
	}

	output, err := c.Sys().UpdateCredentialSpec(name, input)
	if err != nil {
		return fmt.Errorf("error updating credential spec: %w", err)
	}

	fmt.Printf("Success! Updated credential spec: %s\n", output.Name)
	return nil
}
