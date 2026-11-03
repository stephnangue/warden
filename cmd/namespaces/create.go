package namespaces

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	createMetadata           map[string]string
	createJSON               string
	createEnableBuiltinRoles bool

	CreateCmd = &cobra.Command{
		Use:           "create <path>",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "This command creates a new namespace.",
		Long: `
Usage: warden namespace create <path> [options]

  Create a namespace at the specified path. Namespaces isolate providers,
  auth methods, and policies in a multi-tenant environment. Two input modes:

    Typed flags (human-friendly):

      $ warden namespace create my-team
      $ warden namespace create org/engineering
      $ warden namespace create my-team -metadata=environment=prod -metadata=team=platform
      $ warden namespace create acme -enable-builtin-roles

    Full JSON payload (agent-friendly):

      $ warden namespace create my-team -json @ns.json
      $ cat ns.json | warden namespace create my-team -json -

  -enable-builtin-roles makes the built-in operator roles (warden-admin,
  warden-provider-admin, warden-security-admin, warden-viewer) resolvable in
  the new namespace. Its children do not inherit it.

  -json is mutually exclusive with the typed flags. Combine with -dry-run to
  validate the payload locally without creating the namespace.

  For more information about namespaces, please see the documentation.
`,
		Args: cobra.ExactArgs(1),
		RunE: runCreate,
	}
)

func init() {
	CreateCmd.Flags().StringToStringVar(&createMetadata, "metadata", nil, "Custom metadata for the namespace (can be specified multiple times)")
	CreateCmd.Flags().StringVarP(&createJSON, "json", "j", "", "Full JSON payload — '<json>', '@file.json', or '-' for stdin (mutually exclusive with the typed flags)")
	CreateCmd.Flags().BoolVar(&createEnableBuiltinRoles, "enable-builtin-roles", false, "Make the built-in operator roles resolvable in the namespace (not inherited by its children)")
}

func runCreate(cmd *cobra.Command, args []string) error {
	path := args[0]
	if err := helpers.ValidatePath(path); err != nil {
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
			"-metadata":             len(createMetadata) > 0,
			"-enable-builtin-roles": cmd.Flags().Changed("enable-builtin-roles"),
		}); err != nil {
			return err
		}
		if helpers.ResolveDryRun() {
			return helpers.DryRun(c, "POST", "sys/namespaces/{path}", jsonPayload)
		}
		resource, err := c.Operator().Post("sys/namespaces/"+path, jsonPayload)
		if err != nil {
			return fmt.Errorf("error creating namespace: %w", err)
		}
		data := map[string]any{}
		var resData map[string]any
		if resource != nil {
			resData = resource.Data
		}
		helpers.MergeServerResponseInto(data, resData, map[string]any{
			"path":    path,
			"created": true,
		})
		return helpers.RenderMap(data, func() {
			fmt.Printf("Success! Created namespace: %s\n", path)
		})
	}

	// Build namespace create input
	input := &api.CreateNamespaceInput{
		CustomMetadata: createMetadata,
	}
	if cmd.Flags().Changed("enable-builtin-roles") {
		input.EnableBuiltinRoles = &createEnableBuiltinRoles
	}

	if helpers.ResolveDryRun() {
		payload := map[string]any{}
		if len(createMetadata) > 0 {
			md := make(map[string]any, len(createMetadata))
			for k, v := range createMetadata {
				md[k] = v
			}
			payload["custom_metadata"] = md
		}
		if input.EnableBuiltinRoles != nil {
			payload["enable_builtin_roles"] = *input.EnableBuiltinRoles
		}
		return helpers.DryRun(c, "POST", "sys/namespaces/{path}", payload)
	}

	// Create the namespace
	output, err := c.Sys().CreateNamespace(path, input)
	if err != nil {
		return fmt.Errorf("error creating namespace: %w", err)
	}

	data := map[string]any{
		"path":                 output.Path,
		"id":                   output.ID,
		"enable_builtin_roles": output.EnableBuiltinRoles,
		"created":              true,
	}
	if len(output.CustomMetadata) > 0 {
		md := make(map[string]any, len(output.CustomMetadata))
		for k, v := range output.CustomMetadata {
			md[k] = v
		}
		data["custom_metadata"] = md
	}

	return helpers.RenderMap(data, func() {
		fmt.Printf("Success! Created namespace: %s\n", output.Path)
		fmt.Printf("Namespace ID: %s\n", output.ID)
		if output.EnableBuiltinRoles {
			fmt.Println("Built-in roles: enabled")
		}
		if len(output.CustomMetadata) > 0 {
			fmt.Println("\nMetadata:")
			for key, value := range output.CustomMetadata {
				fmt.Printf("  %s = %s\n", key, value)
			}
		}
	})
}
