package providers

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
		Short: "Tune configuration parameters for a provider",
		Long: `
Usage: warden providers tune --path=PATH [--config key=value]...

  Tune configuration parameters for a provider at the given PATH.
  This allows updating provider configuration without unmounting and remounting.

  Update proxy domains for aws provider:

      $ warden providers tune --path=aws/ --config proxy_domains=localhost,warden

  For a full list of tunable parameters, please see the provider documentation.
`,
		RunE: runTune,
	}
)

func init() {
	TuneCmd.Flags().StringVar(&tunePath, "path", "", "Path of the provider to tune (required)")
	TuneCmd.Flags().StringToStringVar(&tuneConfig, "config", nil, "Configuration key-value pairs to update (can be specified multiple times)")
	TuneCmd.MarkFlagRequired("path")
}

// isArrayConfig returns true if the given configuration key is known to be an array type
func isArrayConfig(key string) bool {
	arrayKeys := map[string]bool{
		"proxy_domains": true,
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
		// For keys that are known to be arrays in provider configs
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

	// Tune the provider
	err = c.Sys().TuneMount(tunePath, config)
	if err != nil {
		return fmt.Errorf("error tuning provider at path %s: %w", tunePath, err)
	}

	fmt.Printf("Success! Tuned provider at: %s\n", tunePath)
	return nil
}
