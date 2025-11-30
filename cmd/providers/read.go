package providers

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	readPath string

	ReadCmd = &cobra.Command{
		Use:   "read",
    	SilenceUsage:  true,
		SilenceErrors: true,
		Short: "Show information on a provider",
		Long: `
Usage: warden providers read --path=PATH

  Show information on a provider enabled on the provided PATH.

  Read the provider enabled at aws/:

      $ warden providers read --path=aws/
`,
		RunE: runRead,
	}
)

func init() {
	ReadCmd.Flags().StringVar(&readPath, "path", "", "Path of the provider to read (required)")
	ReadCmd.MarkFlagRequired("path")
}

func runRead(cmd *cobra.Command, args []string) error {
	// Create the client
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	// Get mount info for the specified path
	mountInfo, err := c.Sys().MountInfo(readPath)
	if err != nil {
		return fmt.Errorf("error reading provider at path %s: %w", readPath, err)
	}

	// Display provider information
	headers := []string{"Key", "Value"}
	data := [][]any{
		{"Path", readPath},
		{"Type", mountInfo.Type},
		{"Accessor", mountInfo.Accessor},
		{"Description", mountInfo.Description},
	}

	// Add config entries if present
	if len(mountInfo.Config) > 0 {
		for key, value := range mountInfo.Config {
			data = append(data, []any{fmt.Sprintf("Config.%s", key), value})
		}
	}

	helpers.PrintTable(headers, data)
	return nil
}