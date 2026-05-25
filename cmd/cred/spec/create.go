package spec

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	createType           string
	createSource         string
	createConfig         map[string]string
	createMinTTL         string
	createMaxTTL         string
	createRotationPeriod string
	createJSON           string

	CreateCmd = &cobra.Command{
		Use:   "create <name>",
		Short: "Create a new credential specification",
		Long: `
Usage: warden cred spec create <name> [flags]

  Create a credential spec. Two input modes:

    Typed flags (human-friendly):

      $ warden cred spec create developer \
          -source=my-aws \
          -config=mint_method=sts_assume_role \
          -config=role_arn=arn:aws:iam::1234:role/dev \
          -min-ttl=1h -max-ttl=24h

    Full JSON payload (agent-friendly):

      $ warden cred spec create developer -json @spec.json
      $ cat spec.json | warden cred spec create developer -json -

  -json is mutually exclusive with -type / -source / -config /
  -min-ttl / -max-ttl / -rotation-period. Combine with -dry-run to
  validate the payload locally without creating the spec.
`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.ExactArgs(1),
		RunE:          runCreate,
	}
)

func init() {
	CreateCmd.Flags().StringVar(&createType, "type", "", "Credential type (optional — inferred from source when omitted)")
	CreateCmd.Flags().StringVar(&createSource, "source", "", "Source name (required unless -json)")
	CreateCmd.Flags().StringToStringVar(&createConfig, "config", nil, "Type-specific configuration (key=value)")
	CreateCmd.Flags().StringVar(&createMinTTL, "min-ttl", "1h", "Minimum TTL")
	CreateCmd.Flags().StringVar(&createMaxTTL, "max-ttl", "24h", "Maximum TTL")
	CreateCmd.Flags().StringVar(&createRotationPeriod, "rotation-period", "", "Rotation period for credentials stored in the spec (e.g., '24h', '7d'). Empty means no rotation")
	CreateCmd.Flags().StringVarP(&createJSON, "json", "j", "", "Full JSON payload — '<json>', '@file.json', or '-' for stdin (mutually exclusive with the typed flags)")
}

func runCreate(cmd *cobra.Command, args []string) error {
	name := args[0]
	if err := helpers.ValidatePath(name); err != nil {
		return err
	}

	c, err := helpers.Client()
	if err != nil {
		return err
	}

	jsonPayload, err := helpers.ResolveJSONInput(createJSON)
	if err != nil {
		return err
	}

	if jsonPayload != nil {
		if err := helpers.RejectFlagsWithJSON(true, map[string]bool{
			"-type":            createType != "",
			"-source":          createSource != "",
			"-config":          len(createConfig) > 0,
			"-min-ttl":         cmd.Flags().Changed("min-ttl"),
			"-max-ttl":         cmd.Flags().Changed("max-ttl"),
			"-rotation-period": createRotationPeriod != "",
		}); err != nil {
			return err
		}
		if helpers.ResolveDryRun() {
			return helpers.DryRun(c, "POST", "sys/cred/specs/{name}", jsonPayload)
		}
		resource, err := c.Operator().Post("sys/cred/specs/"+name, jsonPayload)
		if err != nil {
			return fmt.Errorf("error creating credential spec: %w", err)
		}
		data := map[string]any{}
		var resData map[string]any
		if resource != nil {
			resData = resource.Data
		}
		helpers.MergeServerResponseInto(data, resData, map[string]any{
			"name":    name,
			"created": true,
		})
		return helpers.RenderMap(data, func() {
			fmt.Printf("Success! Created credential spec: %s\n", name)
		})
	}

	if createSource == "" {
		return fmt.Errorf("-source is required (or use -json): %w", helpers.ErrUsage)
	}
	if createType != "" {
		if err := helpers.ValidateIdentifier("-type", createType); err != nil {
			return err
		}
	}
	if err := helpers.ValidatePath(createSource); err != nil {
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

	resolvedConfig, err := helpers.ResolveFileRefs(createConfig)
	if err != nil {
		return err
	}

	input := &api.CreateCredentialSpecInput{
		Type:   createType,
		Source: createSource,
		Config: resolvedConfig,
		MinTTL: minTTL,
		MaxTTL: maxTTL,
	}

	// Parse rotation period if provided
	if createRotationPeriod != "" {
		rotationPeriod, err := time.ParseDuration(createRotationPeriod)
		if err != nil {
			return fmt.Errorf("invalid rotation-period: %w", err)
		}
		input.RotationPeriod = rotationPeriod
	}

	if helpers.ResolveDryRun() {
		// Mirror the wire format: durations go out as int64 seconds (see
		// api.CreateCredentialSpec which builds the request body).
		payload := map[string]any{
			"source":  createSource,
			"min_ttl": int64(minTTL.Seconds()),
			"max_ttl": int64(maxTTL.Seconds()),
		}
		if createType != "" {
			payload["type"] = createType
		}
		if len(resolvedConfig) > 0 {
			cfg := make(map[string]any, len(resolvedConfig))
			for k, v := range resolvedConfig {
				cfg[k] = v
			}
			payload["config"] = cfg
		}
		if input.RotationPeriod > 0 {
			payload["rotation_period"] = int64(input.RotationPeriod.Seconds())
		}
		return helpers.DryRun(c, "POST", "sys/cred/specs/{name}", payload)
	}

	output, err := c.Sys().CreateCredentialSpec(name, input)
	if err != nil {
		return fmt.Errorf("error creating credential spec: %w", err)
	}

	data := map[string]any{
		"name":    output.Name,
		"type":    output.Type,
		"source":  output.Source,
		"min_ttl": output.MinTTL.String(),
		"max_ttl": output.MaxTTL.String(),
		"created": true,
	}
	if output.RotationPeriod > 0 {
		data["rotation_period"] = output.RotationPeriod.String()
	}

	return helpers.RenderMap(data, func() {
		fmt.Printf("Success! Created credential spec: %s\n", output.Name)
		fmt.Printf("  Type: %s\n", output.Type)
		fmt.Printf("  Source: %s\n", output.Source)
		fmt.Printf("  Min TTL: %s\n", output.MinTTL)
		fmt.Printf("  Max TTL: %s\n", output.MaxTTL)
		if output.RotationPeriod > 0 {
			fmt.Printf("  Rotation Period: %s\n", output.RotationPeriod)
		}
	})
}
