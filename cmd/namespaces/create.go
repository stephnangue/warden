package namespaces

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	createMetadata map[string]string

	CreateCmd = &cobra.Command{
		Use:           "create <path>",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "This command creates a new namespace.",
		Long: `
Usage: warden namespace create <path> [options]

  Creates a new namespace at the specified path. Namespaces allow you to
  isolate and organize providers, auth methods, and policies in a multi-tenant
  environment.

  Create a simple namespace:

      $ warden namespace create my-team

  Create a nested namespace:

      $ warden namespace create org/engineering

  Create a namespace with custom metadata:

      $ warden namespace create my-team \
          --metadata=environment=production \
          --metadata=team=platform

  For more information about namespaces, please see the documentation.
`,
		Args: cobra.ExactArgs(1),
		RunE: runCreate,
	}
)

func init() {
	CreateCmd.Flags().StringToStringVar(&createMetadata, "metadata", nil, "Custom metadata for the namespace (can be specified multiple times)")
}

func runCreate(cmd *cobra.Command, args []string) error {
	path := args[0]

	// Create the client
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	// Build namespace create input
	input := &api.CreateNamespaceInput{
		CustomMetadata: createMetadata,
	}

	// Create the namespace
	output, err := c.Sys().CreateNamespace(path, input)
	if err != nil {
		return fmt.Errorf("error creating namespace: %w", err)
	}

	fmt.Printf("Success! Created namespace: %s\n", output.Path)
	fmt.Printf("Namespace ID: %s\n", output.ID)

	if len(output.CustomMetadata) > 0 {
		fmt.Println("\nMetadata:")
		for key, value := range output.CustomMetadata {
			fmt.Printf("  %s = %s\n", key, value)
		}
	}

	return nil
}
