package namespaces

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	updateMetadata           map[string]string
	updateJSON               string
	updateEnableBuiltinRoles bool

	UpdateCmd = &cobra.Command{
		Use:           "update <path>",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "This command updates a namespace's metadata and settings.",
		Long: `
Usage: warden namespace update <path> [options]

  Update the custom metadata or the built-in roles setting of an existing
  namespace. Its mounted backends are not affected. Two input modes:

    Typed flags (human-friendly):

      $ warden namespace update my-team -metadata=environment=staging -metadata=team=devops
      $ warden namespace update acme -enable-builtin-roles
      $ warden namespace update acme -enable-builtin-roles=false

    Full JSON payload (agent-friendly):

      $ warden namespace update my-team -json @ns.json
      $ cat ns.json | warden namespace update my-team -json -
      $ warden namespace update my-team -json '{"custom_metadata": {}}'   # clear

  -enable-builtin-roles makes the built-in operator roles (warden-admin,
  warden-provider-admin, warden-security-admin, warden-viewer) resolvable in
  the namespace; its children do not inherit it. Turning it off is refused
  while a group in the namespace grants one of them.

  -json is mutually exclusive with the typed flags. Combine with -dry-run to
  validate the payload locally without modifying the namespace.

  For more information about namespaces, please see the documentation.
`,
		Args: cobra.ExactArgs(1),
		RunE: runUpdate,
	}
)

func init() {
	UpdateCmd.Flags().StringToStringVar(&updateMetadata, "metadata", nil, "Custom metadata for the namespace (can be specified multiple times)")
	UpdateCmd.Flags().StringVarP(&updateJSON, "json", "j", "", "Full JSON payload — '<json>', '@file.json', or '-' for stdin (mutually exclusive with the typed flags)")
	UpdateCmd.Flags().BoolVar(&updateEnableBuiltinRoles, "enable-builtin-roles", false, "Make the built-in operator roles resolvable in the namespace (-enable-builtin-roles=false turns them off)")
}

func runUpdate(cmd *cobra.Command, args []string) error {
	path := args[0]
	if err := helpers.ValidatePath(path); err != nil {
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
			"-metadata":             cmd.Flags().Changed("metadata"),
			"-enable-builtin-roles": cmd.Flags().Changed("enable-builtin-roles"),
		}); err != nil {
			return err
		}
		if helpers.ResolveDryRun() {
			return helpers.DryRun(c, "PUT", "sys/namespaces/{path}", jsonPayload)
		}
		resource, err := c.Operator().Write("sys/namespaces/"+path, jsonPayload)
		if err != nil {
			return fmt.Errorf("error updating namespace: %w", err)
		}
		data := map[string]any{}
		var resData map[string]any
		if resource != nil {
			resData = resource.Data
		}
		helpers.MergeServerResponseInto(data, resData, map[string]any{
			"path":    path,
			"updated": true,
		})
		return helpers.RenderMap(data, func() {
			fmt.Printf("Success! Updated namespace: %s\n", path)
		})
	}

	setMetadata := cmd.Flags().Changed("metadata")
	setBuiltinRoles := cmd.Flags().Changed("enable-builtin-roles")
	if !setMetadata && !setBuiltinRoles {
		return fmt.Errorf("-metadata or -enable-builtin-roles is required (or use -json): %w", helpers.ErrUsage)
	}

	// Build namespace update input
	input := &api.UpdateNamespaceInput{}
	if setMetadata {
		input.CustomMetadata = updateMetadata
	}
	if setBuiltinRoles {
		input.EnableBuiltinRoles = &updateEnableBuiltinRoles
	}

	if helpers.ResolveDryRun() {
		payload := map[string]any{}
		if setMetadata {
			md := make(map[string]any, len(updateMetadata))
			for k, v := range updateMetadata {
				md[k] = v
			}
			payload["custom_metadata"] = md
		}
		if setBuiltinRoles {
			payload["enable_builtin_roles"] = updateEnableBuiltinRoles
		}
		return helpers.DryRun(c, "PUT", "sys/namespaces/{path}", payload)
	}

	// Update the namespace
	output, err := c.Sys().UpdateNamespace(path, input)
	if err != nil {
		return fmt.Errorf("error updating namespace: %w", err)
	}

	data := map[string]any{
		"path":                 output.Path,
		"enable_builtin_roles": output.EnableBuiltinRoles,
		"updated":              true,
	}
	if len(output.CustomMetadata) > 0 {
		md := make(map[string]any, len(output.CustomMetadata))
		for k, v := range output.CustomMetadata {
			md[k] = v
		}
		data["custom_metadata"] = md
	} else {
		data["custom_metadata"] = map[string]any{}
	}

	return helpers.RenderMap(data, func() {
		fmt.Printf("Success! Updated namespace: %s\n", output.Path)
		if setBuiltinRoles {
			if output.EnableBuiltinRoles {
				fmt.Println("Built-in roles: enabled")
			} else {
				fmt.Println("Built-in roles: disabled")
			}
		}
		if !setMetadata {
			return
		}
		if len(output.CustomMetadata) > 0 {
			fmt.Println("\nUpdated Metadata:")
			for key, value := range output.CustomMetadata {
				fmt.Printf("  %s = %s\n", key, value)
			}
		} else {
			fmt.Println("\nMetadata cleared")
		}
	})
}
