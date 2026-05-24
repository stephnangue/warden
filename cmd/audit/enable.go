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
	enablePath        string
	enableJSON        string

	EnableCmd = &cobra.Command{
		Use:           "enable [PATH]",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "This command enables an audit device.",
		Long: `
Usage: warden audit enable [options] [PATH]

  Enable an audit device. By default the mount path matches the TYPE, but a
  custom path can be supplied either positionally or via --path. Each device
  gets a unique HMAC salt for log hashing — generated on enable, lost on
  disable. Note: --path is the device's mount path, while --file-path is the
  audit log file location — they are distinct. Two input modes:

    Typed flags (human-friendly):

      $ warden audit enable --type=file --file-path=/var/log/warden-audit.log
      $ warden audit enable --type=file --file-path=/var/log/audit.log prod-audit
      $ warden audit enable --type=file --file-path=/var/log/audit.log --path=prod-audit

    Full JSON payload (agent-friendly):

      $ warden audit enable file --json @audit-file.json
      $ cat audit-file.json | warden audit enable file --json -

  --json is mutually exclusive with --type / --description / --file-path /
  --format. The mount path may be provided positionally or via --path (pick
  one — combining both is rejected). When neither is set, the path is
  derived from --type or from the JSON payload's "type" field. Combine with
  --dry-run to validate the payload locally without enabling the device.

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
	EnableCmd.Flags().StringVar(&enablePath, "path", "", "Mount path (alternative to the positional PATH argument)")
	EnableCmd.Flags().StringVarP(&enableJSON, "json", "j", "", "Full JSON payload — '<json>', '@file.json', or '-' for stdin (mutually exclusive with the typed flags)")
}

func runEnable(cmd *cobra.Command, args []string) error {
	explicitPath, err := helpers.ResolvePath(args, enablePath)
	if err != nil {
		return err
	}

	c, err := helpers.Client()
	if err != nil {
		return err
	}

	jsonPayload, err := helpers.ResolveJSONInput(enableJSON)
	if err != nil {
		return err
	}

	if jsonPayload != nil {
		if err := helpers.RejectFlagsWithJSON(true, map[string]bool{
			"--type":        cmd.Flags().Changed("type"),
			"--description": enableDescription != "",
			"--file-path":   enableFilePath != "",
			"--format":      cmd.Flags().Changed("format"),
		}); err != nil {
			return err
		}
		path := helpers.MountPathFromArgOrPayload(explicitPath, jsonPayload)
		if path == "" {
			return fmt.Errorf("--json without a PATH (positional or --path) and without a 'type' field in the payload: cannot determine mount path: %w", helpers.ErrUsage)
		}
		if err := helpers.ValidatePath(path); err != nil {
			return err
		}
		if helpers.ResolveDryRun() {
			return helpers.DryRun(c, "POST", "sys/audit/{path}", jsonPayload)
		}
		resource, err := c.Operator().Post("sys/audit/"+path, jsonPayload)
		if err != nil {
			return fmt.Errorf("error enabling audit device: %w", err)
		}
		data := map[string]any{}
		var resData map[string]any
		if resource != nil {
			resData = resource.Data
		}
		helpers.MergeServerResponseInto(data, resData, map[string]any{
			"path":    path,
			"enabled": true,
		})
		return helpers.RenderMap(data, func() {
			fmt.Printf("Success! Enabled audit device at: %s\n", path)
		})
	}

	var path string
	if explicitPath != "" {
		path = explicitPath
	} else {
		path = enableType + "/"
	}
	if !strings.HasSuffix(path, "/") {
		path = path + "/"
	}

	if err := helpers.ValidatePath(path); err != nil {
		return err
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

	if helpers.ResolveDryRun() {
		payload := map[string]any{"type": enableType}
		if enableDescription != "" {
			payload["description"] = enableDescription
		}
		if len(config) > 0 {
			payload["config"] = config
		}
		return helpers.DryRun(c, "POST", "sys/audit/{path}", payload)
	}

	// Enable the audit device
	err = c.Sys().EnableAudit(path, auditInput)
	if err != nil {
		return fmt.Errorf("error enabling audit device: %w", err)
	}

	return helpers.RenderMap(map[string]any{"path": path, "type": enableType, "enabled": true}, func() {
		fmt.Printf("Success! Enabled %s audit device at: %s\n", enableType, path)
	})
}

