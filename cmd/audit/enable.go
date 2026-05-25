package audit

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	enableDescription string
	enableFilePath    string
	enableFormat      string
	enablePath        string
	enableJSON        string

	EnableCmd = &cobra.Command{
		Use:           "enable TYPE",
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "This command enables an audit device.",
		Long: `
Usage: warden audit enable [options] TYPE

  Enable an audit device. TYPE is the device type (currently only "file" is
  supported). By default the mount path matches TYPE; pass -path to mount at
  a custom location. Each device gets a unique HMAC salt for log hashing —
  generated on enable, lost on disable. Note: -path is the device's mount
  path, while -file-path is the audit log file location — they are distinct.
  Two input modes:

    Typed flags (human-friendly):

      $ warden audit enable -file-path=/var/log/warden-audit.log file
      $ warden audit enable -path=prod-audit -file-path=/var/log/audit.log file

    Full JSON payload (agent-friendly):

      $ warden audit enable file -json @audit-file.json
      $ cat audit-file.json | warden audit enable file -json -

  -json is mutually exclusive with -description / -file-path / -format. The
  mount path defaults to TYPE; override it with -path. If the JSON payload
  includes a "type" field, it must match TYPE. Combine with -dry-run to
  validate the payload locally without enabling the device.

  For a full list of audit device types and examples, please see the documentation.
`,
		RunE: runEnable,
	}
)

func init() {
	EnableCmd.Flags().StringVar(&enableDescription, "description", "", "Human-friendly description of the audit device")
	EnableCmd.Flags().StringVar(&enableFilePath, "file-path", "", "Path to the audit log file (required for file type)")
	EnableCmd.Flags().StringVar(&enableFormat, "format", "json", "Log format (currently only 'json' is supported)")
	EnableCmd.Flags().StringVar(&enablePath, "path", "", "Custom mount path (default: TYPE)")
	EnableCmd.Flags().StringVarP(&enableJSON, "json", "j", "", "Full JSON payload — '<json>', '@file.json', or '-' for stdin (mutually exclusive with the typed flags)")
}

func runEnable(cmd *cobra.Command, args []string) error {
	enableType := strings.TrimSuffix(args[0], "/")

	c, err := helpers.Client()
	if err != nil {
		return err
	}

	jsonPayload, err := helpers.ResolveJSONInput(enableJSON)
	if err != nil {
		return err
	}

	path := enablePath
	if path == "" {
		path = enableType
	}
	if !strings.HasSuffix(path, "/") {
		path = path + "/"
	}
	if err := helpers.ValidatePath(path); err != nil {
		return err
	}

	if jsonPayload != nil {
		if err := helpers.RejectFlagsWithJSON(true, map[string]bool{
			"-description": enableDescription != "",
			"-file-path":   enableFilePath != "",
			"-format":      cmd.Flags().Changed("format"),
		}); err != nil {
			return err
		}
		if payloadType, ok := jsonPayload["type"].(string); ok && payloadType != "" && payloadType != enableType {
			return fmt.Errorf(
				"TYPE positional %q disagrees with -json payload \"type\":%q: %w",
				enableType, payloadType, helpers.ErrUsage)
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

	config := make(map[string]any)
	if enableFilePath != "" {
		config["file_path"] = enableFilePath
	}
	if enableFormat != "" {
		config["format"] = enableFormat
	}

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

	err = c.Sys().EnableAudit(path, auditInput)
	if err != nil {
		return fmt.Errorf("error enabling audit device: %w", err)
	}

	return helpers.RenderMap(map[string]any{"path": path, "type": enableType, "enabled": true}, func() {
		fmt.Printf("Success! Enabled %s audit device at: %s\n", enableType, path)
	})
}
