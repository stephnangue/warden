package spec

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	updateSourceParams map[string]string
	updateMinTTL       string
	updateMaxTTL       string

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
	UpdateCmd.Flags().StringToStringVar(&updateSourceParams, "params", nil, "Source parameters (key=value)")
	UpdateCmd.Flags().StringVar(&updateMinTTL, "min-ttl", "", "Minimum TTL")
	UpdateCmd.Flags().StringVar(&updateMaxTTL, "max-ttl", "", "Maximum TTL")
}

func runUpdate(cmd *cobra.Command, args []string) error {
	name := args[0]

	// Require at least one update parameter
	if len(updateSourceParams) == 0 && updateMinTTL == "" && updateMaxTTL == "" {
		return fmt.Errorf("no update parameters provided. Use --params, --min-ttl, or --max-ttl")
	}

	c, err := helpers.Client()
	if err != nil {
		return err
	}

	input := &api.UpdateCredentialSpecInput{
		SourceParams: updateSourceParams,
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

	output, err := c.Sys().UpdateCredentialSpec(name, input)
	if err != nil {
		return fmt.Errorf("error updating credential spec: %w", err)
	}

	fmt.Printf("Success! Updated credential spec: %s\n", output.Name)
	return nil
}
