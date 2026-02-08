package audit

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
	enableFilePath    string
	enableFormat      string

	EnableCmd = &cobra.Command{
		Use:           "enable [PATH]",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "This command enables an audit device.",
		Long: `
Usage: warden audit enable [options] [PATH]

  Enables an audit device. By default, audit devices are enabled at the path
  corresponding to their TYPE, but users can customize the path by providing
  it as a positional argument.

  Each audit device automatically gets a unique HMAC salt for hashing
  sensitive data in logs. This salt is generated on enable and persists
  until the device is disabled.

  Enable a file audit device at file/:

      $ warden audit enable --type=file --file-path=/var/log/warden-audit.log

  Enable with a custom path:

      $ warden audit enable --type=file --file-path=/var/log/audit.log prod-audit

  For a full list of audit device types and examples, please see the documentation.
`,
		RunE: runEnable,
	}
)

func init() {
	EnableCmd.Flags().StringVar(&enableType, "type", "file", "Type of the audit device (currently only 'file' is supported)")
	EnableCmd.Flags().StringVar(&enableDescription, "description", "", "Human-friendly description of the audit device")
	EnableCmd.Flags().StringVar(&enableFilePath, "file-path", "", "Path to the audit log file (required for file type)")
	EnableCmd.Flags().StringVar(&enableFormat, "format", "json", "Log format (currently only 'json' is supported)")
}

func runEnable(cmd *cobra.Command, args []string) error {
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	// Determine path from positional argument or use type as default
	var path string
	if len(args) > 0 {
		path = args[0]
	} else {
		path = enableType + "/"
	}

	// Ensure path ends with /
	if !strings.HasSuffix(path, "/") {
		path = path + "/"
	}

	// Build config
	config := make(map[string]any)
	if enableFilePath != "" {
		config["file_path"] = enableFilePath
	}
	if enableFormat != "" {
		config["format"] = enableFormat
	}

	// Build audit input
	auditInput := &api.AuditInput{
		Type:        enableType,
		Description: enableDescription,
		Config:      config,
	}

	// Enable the audit device
	err = c.Sys().EnableAudit(path, auditInput)
	if err != nil {
		return fmt.Errorf("error enabling audit device: %w", err)
	}

	fmt.Printf("Success! Enabled %s audit device at: %s\n", enableType, path)
	return nil
}
