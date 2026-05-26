package source

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	updateConfig map[string]string
	updateJSON   string

	UpdateCmd = &cobra.Command{
		Use:   "update <name>",
		Short: "Update a credential source",
		Long: `
Usage: warden cred source update <name> [flags]

  Update an existing credential source. Two input modes:

    Typed flags (human-friendly):

      $ warden cred source update my-aws -config=region=eu-west-1

    Full JSON payload (agent-friendly):

      $ warden cred source update my-aws -json @aws-source.json
      $ cat aws-source.json | warden cred source update my-aws -json -

  -json is mutually exclusive with -config. Combine with -dry-run to
  validate the payload locally without modifying the source.
`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.ExactArgs(1),
		RunE:          runUpdate,
	}
)

func init() {
	UpdateCmd.Flags().StringToStringVar(&updateConfig, "config", nil, "Source configuration (key=value)")
	UpdateCmd.Flags().StringVarP(&updateJSON, "json", "j", "", "Full JSON payload — '<json>', '@file.json', or '-' for stdin (mutually exclusive with -config)")
}

func runUpdate(cmd *cobra.Command, args []string) error {
	name := args[0]
	if err := helpers.ValidatePath(name); err != nil {
		return err
	}

	c, err := helpers.Client()
	if err != nil {
		return err
	}

	jsonPayload, err := helpers.ResolveJSONInput(updateJSON)
	if err != nil {
		return err
	}

	if jsonPayload != nil {
		if err := helpers.RejectFlagsWithJSON(true, map[string]bool{
			"-config": len(updateConfig) > 0,
		}); err != nil {
			return err
		}
		if helpers.ResolveDryRun() {
			return helpers.DryRun(c, "PUT", "sys/cred/sources/{name}", jsonPayload)
		}
		resource, err := c.Operator().Write("sys/cred/sources/"+name, jsonPayload)
		if err != nil {
			return fmt.Errorf("error updating credential source: %w", err)
		}
		data := map[string]any{}
		var resData map[string]any
		if resource != nil {
			resData = resource.Data
		}
		helpers.MergeServerResponseInto(data, resData, map[string]any{
			"name":    name,
			"updated": true,
		})
		return helpers.RenderMap(data, func() {
			fmt.Printf("Success! Updated credential source: %s\n", name)
		})
	}

	if len(updateConfig) == 0 {
		return fmt.Errorf("-config is required (or use -json): %w", helpers.ErrUsage)
	}

	resolvedConfig, err := helpers.ResolveFileRefs(updateConfig)
	if err != nil {
		return err
	}

	input := &api.UpdateCredentialSourceInput{
		Config: resolvedConfig,
	}

	if helpers.ResolveDryRun() {
		payload := map[string]any{}
		if len(resolvedConfig) > 0 {
			payload["config"] = mapStringStringToAny(resolvedConfig)
		}
		return helpers.DryRun(c, "PUT", "sys/cred/sources/{name}", payload)
	}

	output, err := c.Sys().UpdateCredentialSource(name, input)
	if err != nil {
		return fmt.Errorf("error updating credential source: %w", err)
	}

	return helpers.RenderMap(map[string]any{"name": output.Name, "updated": true}, func() {
		fmt.Printf("Success! Updated credential source: %s\n", output.Name)
	})
}
