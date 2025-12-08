package auth

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	enableType         string
	enablePath         string
	enableDescription  string

	EnableCmd = &cobra.Command{
		Use:   "enable",
    	SilenceUsage:  true,
		SilenceErrors: true,
		Short: "This command enables an auth method.",
		Long: `
Usage: warden auth enable [options]

  Enables an auth method. By default, auth methods are enabled at the path
  corresponding to their TYPE, but users can customize the path using the
  --path option.

  Once enabled, Warden will route all authentication requests which begin
  with the path to the auth method.

  Enable the JWT auth method at jwt/:

      $ warden auth enable --type=jwt

  Enable the OIDC auth method at oidc-prod/:

      $ warden auth enable --type=oidc --path=oidc-prod

  For a full list of auth methods and examples, please see the documentation.
`,
		RunE: runEnable,
	}
)

func init() {
	EnableCmd.Flags().StringVar(&enableType, "type", "", "Type of the auth method (e.g., jwt, oidc, ldap) (required)")
	EnableCmd.Flags().StringVar(&enablePath, "path", "", "Path where the auth method will be mounted (default: <type>/)")
	EnableCmd.Flags().StringVar(&enableDescription, "description", "", "Human-friendly description of the auth method")
	EnableCmd.MarkFlagRequired("type")
}

func runEnable(cmd *cobra.Command, args []string) error {
	// Create the client
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	// Use type as default path if path is not specified
	path := enablePath
	if path == "" {
		path = enableType + "/"
	}

	// Ensure path ends with /
	if !strings.HasSuffix(path, "/") {
		path = path + "/"
	}

	// Build auth mount input
	authInput := &api.AuthMounthInput{
		Type:        enableType,
		Description: enableDescription,
	}

	// Enable the auth method
	err = c.Sys().EnableAuth(path, authInput)
	if err != nil {
		return fmt.Errorf("error enabling auth method: %w", err)
	}

	fmt.Printf("Success! Enabled %s auth method at: %s\n", enableType, path)
	return nil
}
