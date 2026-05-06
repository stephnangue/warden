package namespaces

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	updateMetadata map[string]string

	UpdateCmd = &cobra.Command{
		Use:           "update <path>",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "This command updates a namespace's metadata.",
		Long: `
Usage: warden namespace update <path> [options]

  Updates the custom metadata for an existing namespace. This command allows
  you to modify the metadata without affecting the namespace's configuration
  or mounted backends.

  Update namespace metadata:

      $ warden namespace update my-team \
          --metadata=environment=staging \
          --metadata=team=devops

  Clear all metadata by providing empty values:

      $ warden namespace update my-team --metadata=""

  For more information about namespaces, please see the documentation.
`,
		Args: cobra.ExactArgs(1),
		RunE: runUpdate,
	}
)

func init() {
	UpdateCmd.Flags().StringToStringVar(&updateMetadata, "metadata", nil, "Custom metadata for the namespace (can be specified multiple times)")
	UpdateCmd.MarkFlagRequired("metadata")
}

func runUpdate(cmd *cobra.Command, args []string) error {
	path := args[0]
	if err := helpers.ValidatePath(path); err != nil {
		return err
	}

	// Create the client
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	// Build namespace update input
	input := &api.UpdateNamespaceInput{
		CustomMetadata: updateMetadata,
	}

	if helpers.ResolveDryRun() {
		md := make(map[string]any, len(updateMetadata))
		for k, v := range updateMetadata {
			md[k] = v
		}
		payload := map[string]any{"custom_metadata": md}
		return helpers.DryRun(c, "PUT", "sys/namespaces/{path}", payload)
	}

	// Update the namespace
	output, err := c.Sys().UpdateNamespace(path, input)
	if err != nil {
		return fmt.Errorf("error updating namespace: %w", err)
	}

	data := map[string]any{
		"path":    output.Path,
		"updated": true,
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
