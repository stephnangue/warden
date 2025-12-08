package auth

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
		Short: "Show information on an auth method",
		Long: `
Usage: warden auth read --path=PATH

  Show information on an auth method enabled on the provided PATH.

  Read the auth method enabled at jwt/:

      $ warden auth read --path=jwt/
`,
		RunE: runRead,
	}
)

func init() {
	ReadCmd.Flags().StringVar(&readPath, "path", "", "Path of the auth method to read (required)")
	ReadCmd.MarkFlagRequired("path")
}

func runRead(cmd *cobra.Command, args []string) error {
	// Create the client
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	// Get auth method info for the specified path
	authInfo, err := c.Sys().AuthInfo(readPath)
	if err != nil {
		return fmt.Errorf("error reading auth method at path %s: %w", readPath, err)
	}

	// Display auth method information
	headers := []string{"Key", "Value"}
	data := [][]any{
		{"path", readPath},
		{"type", authInfo.Type},
		{"accessor", authInfo.Accessor},
		{"description", authInfo.Description},
	}

	// Add config entries if present
	if len(authInfo.Config) > 0 {
		for key, value := range authInfo.Config {
			data = append(data, []any{key, value})
		}
	}

	helpers.PrintTable(headers, data)
	return nil
}
