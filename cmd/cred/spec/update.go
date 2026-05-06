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
	if err := helpers.ValidatePath(name); err != nil {
		return err
	}

	// Require at least one update parameter
	if len(updateConfig) == 0 && updateMinTTL == "" && updateMaxTTL == "" && updateRotationPeriod == "" {
		return fmt.Errorf("no update parameters provided (use --config, --min-ttl, --max-ttl, or --rotation-period): %w", helpers.ErrInvalidInput)
	}

	c, err := helpers.Client()
	if err != nil {
		return err
	}

	resolvedConfig, err := helpers.ResolveFileRefs(updateConfig)
	if err != nil {
		return err
	}

	input := &api.UpdateCredentialSpecInput{
		Config: resolvedConfig,
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

	if helpers.ResolveDryRun() {
		payload := map[string]any{}
		if len(resolvedConfig) > 0 {
			cfg := make(map[string]any, len(resolvedConfig))
			for k, v := range resolvedConfig {
				cfg[k] = v
			}
			payload["config"] = cfg
		}
		// Mirror the wire format: durations go out as int64 seconds (see
		// api.UpdateCredentialSpec which builds the request body).
		if input.MinTTL != nil {
			payload["min_ttl"] = int64(input.MinTTL.Seconds())
		}
		if input.MaxTTL != nil {
			payload["max_ttl"] = int64(input.MaxTTL.Seconds())
		}
		if input.RotationPeriod != nil {
			payload["rotation_period"] = int64(input.RotationPeriod.Seconds())
		}
		return helpers.DryRun(c, "PUT", "sys/cred/specs/{name}", payload)
	}

	output, err := c.Sys().UpdateCredentialSpec(name, input)
	if err != nil {
		return fmt.Errorf("error updating credential spec: %w", err)
	}

	return helpers.RenderMap(map[string]any{"name": output.Name, "updated": true}, func() {
		fmt.Printf("Success! Updated credential spec: %s\n", output.Name)
	})
}
