package auth

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
		Short:         "This command enables an auth method.",
		Long: `
Usage: warden auth enable [options] [PATH]

  Enable an auth method. By default the mount path matches the TYPE, but a
  custom path can be supplied either positionally or via --path. Two input
  modes:

    Typed flags (human-friendly):

      $ warden auth enable --type=jwt
      $ warden auth enable --type=oidc oidc-prod
      $ warden auth enable --type=oidc --path=oidc-prod
      $ warden auth enable --type=jwt --description="Hydra OIDC"

    Full JSON payload (agent-friendly):

      $ warden auth enable jwt --json @auth-jwt.json
      $ warden auth enable jwt --json '{"type":"jwt","description":"..."}'
      $ cat auth-jwt.json | warden auth enable jwt --json -

  --json is mutually exclusive with --type / --description. The mount path
  may be provided positionally or via --path (pick one — combining both is
  rejected). When neither is set, the path is derived from --type or from
  the JSON payload's "type" field (e.g. type "jwt" → mount "jwt/"). Combine
  with --dry-run to validate the payload locally without enabling the mount.

  For a full list of auth methods and examples, please see the documentation.
`,
		RunE: runEnable,
	}
)

func init() {
	EnableCmd.Flags().StringVar(&enableType, "type", "", "Type of the auth method (e.g., jwt, oidc, ldap) (required unless --json)")
	EnableCmd.Flags().StringVar(&enableDescription, "description", "", "Human-friendly description of the auth method")
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
		// --json mode still needs a path — use the explicit path (positional
		// or --path) or derive it from the payload's "type" field.
		path := helpers.MountPathFromArgOrPayload(explicitPath, jsonPayload)
		if path == "" {
			return fmt.Errorf("--json without a PATH (positional or --path) and without a 'type' field in the payload: cannot determine mount path: %w", helpers.ErrUsage)
		}
		if err := helpers.ValidatePath(path); err != nil {
			return err
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

	// Build auth mount input
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

	// Enable the auth method
	err = c.Sys().EnableAuth(path, authInput)
	if err != nil {
		return fmt.Errorf("error enabling auth method: %w", err)
	}

	return helpers.RenderMap(map[string]any{"path": path, "type": enableType, "enabled": true}, func() {
		fmt.Printf("Success! Enabled %s auth method at: %s\n", enableType, path)
	})
}

