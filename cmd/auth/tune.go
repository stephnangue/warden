package auth

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	tunePath   string
	tuneConfig map[string]string

	TuneCmd = &cobra.Command{
		Use:   "tune",
    	SilenceUsage:  true,
		SilenceErrors: true,
		Short: "Tune configuration parameters for an auth method",
		Long: `
Usage: warden auth tune --path=PATH [--config key=value]...

  Tune configuration parameters for an auth method at the given PATH.
  This allows updating auth method configuration without disabling and re-enabling.

  Update token TTL for JWT auth method:

      $ warden auth tune --path=jwt/ --config default_lease_ttl=1h

  For a full list of tunable parameters, please see the auth method documentation.
`,
		RunE: runTune,
	}
)

func init() {
	TuneCmd.Flags().StringVar(&tunePath, "path", "", "Path of the auth method to tune (required)")
	TuneCmd.Flags().StringToStringVar(&tuneConfig, "config", nil, "Configuration key-value pairs to update (can be specified multiple times)")
	TuneCmd.MarkFlagRequired("path")
}

// isArrayConfig returns true if the given configuration key is known to be an array type
func isArrayConfig(key string) bool {
	arrayKeys := map[string]bool{
		"bound_audiences": true,
		"bound_claims":    true,
		// Add other array-type config keys here as needed
	}
	return arrayKeys[key]
}

func runTune(cmd *cobra.Command, args []string) error {
	// Create the client
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	// Check if config is provided
	if len(tuneConfig) == 0 {
		return fmt.Errorf("no configuration parameters provided. Use --config key=value")
	}

	// Convert string map to any map, parsing comma-separated values as arrays
	config := make(map[string]any)
	for key, value := range tuneConfig {
		// Parse array-like configuration (comma-separated values)
		// For keys that are known to be arrays in auth method configs
		if isArrayConfig(key) && strings.Contains(value, ",") {
			// Split by comma and trim whitespace
			parts := strings.Split(value, ",")
			array := make([]string, len(parts))
			for i, part := range parts {
				array[i] = strings.TrimSpace(part)
			}
			config[key] = array
		} else {
			config[key] = value
		}
	}

	// Tune the auth method
	err = c.Sys().TuneAuth(tunePath, config)
	if err != nil {
		return fmt.Errorf("error tuning auth method at path %s: %w", tunePath, err)
	}

	fmt.Printf("Success! Tuned auth method at: %s\n", tunePath)
	return nil
}
