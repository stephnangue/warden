package auth

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	ReadCmd = &cobra.Command{
		Use:           "read PATH",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Show information on an auth method",
		Long: `
Usage: warden auth read PATH

  Show information on an auth method enabled on the provided PATH.

  Read the auth method enabled at jwt/:

      $ warden auth read jwt/
`,
		Args: cobra.ExactArgs(1),
		RunE: runRead,
	}
)

func runRead(cmd *cobra.Command, args []string) error {
	// Create the client
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	path := args[0]

	// Get auth method info for the specified path
	authInfo, err := c.Sys().AuthInfo(path)
	if err != nil {
		return fmt.Errorf("error reading auth method at path %s: %w", path, err)
	}

	// Display auth method information
	headers := []string{"Key", "Value"}
	data := [][]any{
		{"path", path},
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
