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
	enablePath        string
	enableJSON        string

	EnableCmd = &cobra.Command{
		Use:           "enable [PATH]",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "This command enable a provider.",
		Long: `
Usage: warden provider enable [options] [PATH]

  Enable a provider. By default the mount path matches the TYPE, but a
  custom path can be supplied either positionally or via --path. Two input
  modes:

    Typed flags (human-friendly):

      $ warden provider enable --type=aws
      $ warden provider enable --type=azure azure-prod
      $ warden provider enable --type=azure --path=azure-prod
      $ warden provider enable --type=aws --description="Production AWS"

    Full JSON payload (agent-friendly):

      $ warden provider enable aws --json @provider-aws.json
      $ cat provider-aws.json | warden provider enable aws --json -

  --json is mutually exclusive with --type / --description. The mount path
  may be provided positionally or via --path (pick one — combining both is
  rejected). When neither is set, the path is derived from --type or from
  the JSON payload's "type" field. Combine with --dry-run to validate the
  payload locally without enabling the provider.

  For a full list of providers and examples, please see the documentation.
`,
		RunE: runEnable,
	}
)

func init() {
	EnableCmd.Flags().StringVar(&enableType, "type", "", "Type of the provider (e.g., aws, azure, gcp) (required unless --json)")
	EnableCmd.Flags().StringVar(&enableDescription, "description", "", "Human-friendly description of the provider")
	EnableCmd.Flags().StringVar(&enablePath, "path", "", "Mount path (alternative to the positional PATH argument)")
	EnableCmd.Flags().StringVarP(&enableJSON, "json", "j", "", "Full JSON payload — '<json>', '@file.json', or '-' for stdin (mutually exclusive with --type/--description)")
}

func runEnable(cmd *cobra.Command, args []string) error {
	explicitPath, err := helpers.ResolvePath(args, enablePath)
	if err != nil {
		return err
	}

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
		path := helpers.MountPathFromArgOrPayload(explicitPath, jsonPayload)
		if path == "" {
			return fmt.Errorf("--json without a PATH (positional or --path) and without a 'type' field in the payload: cannot determine mount path: %w", helpers.ErrUsage)
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

	var path string
	if explicitPath != "" {
		path = explicitPath
	} else {
		path = enableType + "/"
	}
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

