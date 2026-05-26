package auth

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
		Short:         "This command enables an auth method.",
		Long: `
Usage: warden auth enable [options] TYPE

  Enable an auth method. TYPE is the auth method to enable (e.g. jwt, oidc).
  By default the mount path matches TYPE; pass -path to mount at a custom
  location. Two input modes:

    Typed flags (human-friendly):

      $ warden auth enable jwt
      $ warden auth enable -path=jwt-prod jwt
      $ warden auth enable -description="Hydra OIDC" jwt

    Full JSON payload (agent-friendly):

      $ warden auth enable jwt -json @auth-jwt.json
      $ warden auth enable jwt -json '{"type":"jwt","description":"..."}'
      $ cat auth-jwt.json | warden auth enable jwt -json -

  -json is mutually exclusive with -description. The mount path defaults to
  TYPE; override it with -path. If the JSON payload includes a "type" field,
  it must match TYPE. Combine with -dry-run to validate the payload locally
  without enabling the mount.

  For a full list of auth methods and examples, please see the documentation.
`,
		RunE: runEnable,
	}
)

func init() {
	EnableCmd.Flags().StringVar(&enableDescription, "description", "", "Human-friendly description of the auth method")
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
			return helpers.DryRun(c, "POST", "sys/auth/{path}", jsonPayload)
		}
		resource, err := c.Operator().Post("sys/auth/"+path, jsonPayload)
		if err != nil {
			return fmt.Errorf("error enabling auth method: %w", err)
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
			fmt.Printf("Success! Enabled auth method at: %s\n", path)
		})
	}

	authInput := &api.AuthMountInput{
		Type:        enableType,
		Description: enableDescription,
	}

	if helpers.ResolveDryRun() {
		payload := map[string]any{"type": enableType}
		if enableDescription != "" {
			payload["description"] = enableDescription
		}
		return helpers.DryRun(c, "POST", "sys/auth/{path}", payload)
	}

	err = c.Sys().EnableAuth(path, authInput)
	if err != nil {
		return fmt.Errorf("error enabling auth method: %w", err)
	}

	return helpers.RenderMap(map[string]any{"path": path, "type": enableType, "enabled": true}, func() {
		fmt.Printf("Success! Enabled %s auth method at: %s\n", enableType, path)
	})
}
