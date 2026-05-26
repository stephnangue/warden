package providers

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	enableDescription string
	enablePath        string
	enableJSON        string

	EnableCmd = &cobra.Command{
		Use:           "enable TYPE",
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "This command enables a provider.",
		Long: `
Usage: warden provider enable [options] TYPE

  Enable a provider. TYPE is the provider to enable (e.g. aws, azure, gcp).
  By default the mount path matches TYPE; pass -path to mount at a custom
  location. Two input modes:

    Typed flags (human-friendly):

      $ warden provider enable aws
      $ warden provider enable -path=azure-prod azure
      $ warden provider enable -description="Production AWS" aws

    Full JSON payload (agent-friendly):

      $ warden provider enable aws -json @provider-aws.json
      $ cat provider-aws.json | warden provider enable aws -json -

  -json is mutually exclusive with -description. The mount path defaults to
  TYPE; override it with -path. If the JSON payload includes a "type" field,
  it must match TYPE. Combine with -dry-run to validate the payload locally
  without enabling the provider.

  For a full list of providers and examples, please see the documentation.
`,
		RunE: runEnable,
	}
)

func init() {
	EnableCmd.Flags().StringVar(&enableDescription, "description", "", "Human-friendly description of the provider")
	EnableCmd.Flags().StringVar(&enablePath, "path", "", "Custom mount path (default: TYPE)")
	EnableCmd.Flags().StringVarP(&enableJSON, "json", "j", "", "Full JSON payload — '<json>', '@file.json', or '-' for stdin (mutually exclusive with -description)")
}

func runEnable(cmd *cobra.Command, args []string) error {
	enableType := strings.TrimSuffix(args[0], "/")

	c, err := helpers.Client()
	if err != nil {
		return err
	}

	jsonPayload, err := helpers.ResolveJSONInput(enableJSON)
	if err != nil {
		return err
	}

	path := enablePath
	if path == "" {
		path = enableType
	}
	if !strings.HasSuffix(path, "/") {
		path = path + "/"
	}
	if err := helpers.ValidatePath(path); err != nil {
		return err
	}

	if jsonPayload != nil {
		if err := helpers.RejectFlagsWithJSON(true, map[string]bool{
			"-description": enableDescription != "",
		}); err != nil {
			return err
		}
		if payloadType, ok := jsonPayload["type"].(string); ok && payloadType != "" && payloadType != enableType {
			return fmt.Errorf(
				"TYPE positional %q disagrees with -json payload \"type\":%q: %w",
				enableType, payloadType, helpers.ErrUsage)
		}
		if helpers.ResolveDryRun() {
			return helpers.DryRun(c, "POST", "sys/providers/{path}", jsonPayload)
		}
		resource, err := c.Operator().Post("sys/providers/"+path, jsonPayload)
		if err != nil {
			return fmt.Errorf("error enabling provider: %w", err)
		}
		data := map[string]any{}
		var resData map[string]any
		if resource != nil {
			resData = resource.Data
		}
		helpers.MergeServerResponseInto(data, resData, map[string]any{
			"path":    path,
			"enabled": true,
		})
		return helpers.RenderMap(data, func() {
			fmt.Printf("Success! Enabled provider at: %s\n", path)
		})
	}

	mountInput := &api.MountInput{
		Type:        enableType,
		Description: enableDescription,
	}

	if helpers.ResolveDryRun() {
		payload := map[string]any{"type": enableType}
		if enableDescription != "" {
			payload["description"] = enableDescription
		}
		return helpers.DryRun(c, "POST", "sys/providers/{path}", payload)
	}

	err = c.Sys().Mount(path, mountInput)
	if err != nil {
		return fmt.Errorf("error enabling provider: %w", err)
	}

	return helpers.RenderMap(map[string]any{"path": path, "type": enableType, "enabled": true}, func() {
		fmt.Printf("Success! Enabled %s provider at: %s\n", enableType, path)
	})
}
