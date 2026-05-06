package providers

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	enableType        string
	enableDescription string
	enableJSON        string

	EnableCmd = &cobra.Command{
		Use:           "enable [PATH]",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "This command enable a provider.",
		Long: `
Usage: warden provider enable [options] [PATH]

  Enable a provider. By default the mount path matches the TYPE, but a
  custom path can be supplied as a positional argument. Two input modes:

    Typed flags (human-friendly):

      $ warden provider enable --type=aws
      $ warden provider enable --type=azure azure-prod
      $ warden provider enable --type=aws --description="Production AWS"

    Full JSON payload (agent-friendly):

      $ warden provider enable aws --json @provider-aws.json
      $ cat provider-aws.json | warden provider enable aws --json -

  --json is mutually exclusive with --type / --description. The mount path
  is the positional argument when given, otherwise derived from the
  payload's "type" field. Combine with --dry-run to validate the payload
  locally without enabling the provider.

  For a full list of providers and examples, please see the documentation.
`,
		RunE: runEnable,
	}
)

func init() {
	EnableCmd.Flags().StringVar(&enableType, "type", "", "Type of the provider (e.g., aws, azure, gcp) (required unless --json)")
	EnableCmd.Flags().StringVar(&enableDescription, "description", "", "Human-friendly description of the provider")
	EnableCmd.Flags().StringVarP(&enableJSON, "json", "j", "", "Full JSON payload — '<json>', '@file.json', or '-' for stdin (mutually exclusive with --type/--description)")
}

func runEnable(cmd *cobra.Command, args []string) error {
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	jsonPayload, err := helpers.ResolveJSONInput(enableJSON)
	if err != nil {
		return err
	}

	if jsonPayload != nil {
		if err := helpers.RejectFlagsWithJSON(true, map[string]bool{
			"--type":        enableType != "",
			"--description": enableDescription != "",
		}); err != nil {
			return err
		}
		path := helpers.MountPathFromArgOrPayload(args, jsonPayload)
		if path == "" {
			return fmt.Errorf("--json without a positional PATH and without a 'type' field in the payload: cannot determine mount path: %w", helpers.ErrUsage)
		}
		if err := helpers.ValidatePath(path); err != nil {
			return err
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

	if enableType == "" {
		return fmt.Errorf("--type is required (or use --json): %w", helpers.ErrUsage)
	}

	// Determine path from positional argument or use type as default
	var path string
	if len(args) > 0 {
		path = args[0]
	} else {
		path = enableType + "/"
	}

	// Ensure path ends with /
	if !strings.HasSuffix(path, "/") {
		path = path + "/"
	}

	if err := helpers.ValidatePath(path); err != nil {
		return err
	}

	// Build mount input
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

	// Mount the provider
	err = c.Sys().Mount(path, mountInput)
	if err != nil {
		return fmt.Errorf("error enabling provider: %w", err)
	}

	return helpers.RenderMap(map[string]any{"path": path, "type": enableType, "enabled": true}, func() {
		fmt.Printf("Success! Enabled %s provider at: %s\n", enableType, path)
	})
}

