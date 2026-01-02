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

	// Create the client
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	// Build namespace update input
	input := &api.UpdateNamespaceInput{
		CustomMetadata: updateMetadata,
	}

	// Update the namespace
	output, err := c.Sys().UpdateNamespace(path, input)
	if err != nil {
		return fmt.Errorf("error updating namespace: %w", err)
	}

	fmt.Printf("Success! Updated namespace: %s\n", output.Path)

	if len(output.CustomMetadata) > 0 {
		fmt.Println("\nUpdated Metadata:")
		for key, value := range output.CustomMetadata {
			fmt.Printf("  %s = %s\n", key, value)
		}
	} else {
		fmt.Println("\nMetadata cleared")
	}

	return nil
}
