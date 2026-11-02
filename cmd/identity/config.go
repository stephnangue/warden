package identity

import (
	"fmt"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	configUnknownAliases string
	configExemptMounts   []string
	configForce          bool
	configJSON           string

	ConfigCmd = &cobra.Command{
		Use:   "config",
		Short: "Read or write the namespace's identity verdict settings (sudo)",
		Long: `
Usage: warden identity config <subcommand> [options]

  The identity config decides how the namespace treats a caller by its
  native identity, before any role is considered:

    unknown_aliases  observe (default): callers no entity claims are
                     admitted as before.
                     deny: they are refused, and so is a claimed caller
                     whose entity is not governed, unless their mount is
                     exempt.
    exempt_mounts    auth mounts deny never applies to, e.g. a CI
                     mount whose callers are anonymous by design.

  A claimed caller whose entity is suspended or retired is refused in
  every mode. People signed in with 'warden login' are never refused for
  their native identity.

      $ warden identity config read
      $ warden identity config write -json '{
          "unknown_aliases": "deny",
          "exempt_mounts": ["auth/github-oidc/"]
        }'
      $ warden identity config reset

  Please see the individual subcommand help for detailed usage information.
`,
	}

	ConfigReadCmd = &cobra.Command{
		Use:           "read",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Read the namespace's identity config (sudo)",
		Args:          cobra.NoArgs,
		RunE:          runConfigRead,
	}

	ConfigWriteCmd = &cobra.Command{
		Use:           "write",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Write the namespace's identity config (sudo)",
		Long: `
Usage: warden identity config write [options]

  Write the fields you name; the others keep their value. -exempt-mount
  replaces the whole list (repeat it, or pass -exempt-mount="" to clear
  it). A config that would refuse your own requests is refused unless you
  pass -force. Requires a token with sudo on sys/identity/config.

      $ warden identity config write -json '{
          "unknown_aliases": "deny",
          "exempt_mounts": ["auth/github-oidc/"]
        }'

      $ warden identity config write -unknown-aliases=deny -exempt-mount=auth/github-oidc/
      $ warden identity config write -unknown-aliases=observe
`,
		Args: cobra.NoArgs,
		RunE: runConfigWrite,
	}

	ConfigResetCmd = &cobra.Command{
		Use:           "reset",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Restore the defaults of the namespace's identity config (sudo)",
		Args:          cobra.NoArgs,
		RunE:          runConfigReset,
	}
)

func init() {
	fs := ConfigWriteCmd.Flags()
	fs.StringVar(&configUnknownAliases, "unknown-aliases", "", `"observe" or "deny"`)
	fs.StringSliceVar(&configExemptMounts, "exempt-mount", nil,
		"An auth mount deny never applies to, by path (repeatable; replaces the list)")
	fs.BoolVar(&configForce, "force", false, "Write a config that would refuse your own requests")
	fs.StringVarP(&configJSON, "json", "j", "",
		"Full JSON payload — '<json>', '@file.json', or '-' for stdin (mutually exclusive with the typed flags)")

	ConfigCmd.AddCommand(ConfigReadCmd)
	ConfigCmd.AddCommand(ConfigWriteCmd)
	ConfigCmd.AddCommand(ConfigResetCmd)
}

// configKeys are the fields of a config write's -json payload.
var configKeys = []string{"unknown_aliases", "exempt_mounts", "force"}

func runConfigRead(cmd *cobra.Command, args []string) error {
	c, err := helpers.Client()
	if err != nil {
		return err
	}
	cfg, err := c.Sys().ReadIdentityConfig()
	if err != nil {
		return fmt.Errorf("error reading the identity config: %w", err)
	}
	return renderConfig(cfg)
}

func runConfigWrite(cmd *cobra.Command, args []string) error {
	var input api.IdentityConfigInput
	payload, err := helpers.ResolveJSONInput(configJSON)
	if err != nil {
		return err
	}
	if payload != nil {
		changed := map[string]bool{}
		for _, flag := range []string{"unknown-aliases", "exempt-mount", "force"} {
			changed["-"+flag] = cmd.Flags().Changed(flag)
		}
		if err := helpers.RejectFlagsWithJSON(true, changed); err != nil {
			return err
		}
		for k, v := range payload {
			switch k {
			case "unknown_aliases":
				s, ok := v.(string)
				if !ok {
					return fmt.Errorf("%q must be a string: %w", k, helpers.ErrUsage)
				}
				input.UnknownAliases = s
			case "exempt_mounts":
				list, ok := v.([]any)
				if !ok {
					return fmt.Errorf("%q must be a list of mount paths: %w", k, helpers.ErrUsage)
				}
				input.ExemptMounts = []string{}
				for _, item := range list {
					s, ok := item.(string)
					if !ok {
						return fmt.Errorf("%q must be a list of mount paths: %w", k, helpers.ErrUsage)
					}
					input.ExemptMounts = append(input.ExemptMounts, s)
				}
			case "force":
				b, ok := v.(bool)
				if !ok {
					return fmt.Errorf("%q must be a boolean: %w", k, helpers.ErrUsage)
				}
				input.Force = b
			default:
				return fmt.Errorf("unknown field %q: the payload takes %s: %w", k, strings.Join(configKeys, ", "), helpers.ErrUsage)
			}
		}
	} else {
		input.UnknownAliases, input.Force = configUnknownAliases, configForce
		if cmd.Flags().Changed("exempt-mount") {
			input.ExemptMounts = slices.DeleteFunc(slices.Clone(configExemptMounts), func(s string) bool { return s == "" })
		}
	}
	if input.UnknownAliases == "" && input.ExemptMounts == nil {
		return fmt.Errorf("nothing to write: set unknown_aliases or exempt_mounts: %w", helpers.ErrUsage)
	}

	c, err := helpers.Client()
	if err != nil {
		return err
	}
	cfg, err := c.Sys().WriteIdentityConfig(&input)
	if err != nil {
		return fmt.Errorf("error writing the identity config: %w", err)
	}
	return renderConfig(cfg)
}

func runConfigReset(cmd *cobra.Command, args []string) error {
	c, err := helpers.Client()
	if err != nil {
		return err
	}
	cfg, err := c.Sys().ResetIdentityConfig()
	if err != nil {
		return fmt.Errorf("error resetting the identity config: %w", err)
	}
	return renderConfig(cfg)
}

// renderConfig prints cfg, its warnings on stderr.
func renderConfig(cfg *api.IdentityConfig) error {
	helpers.PrintWarnings(cfg.Warnings)
	exempt := make([]any, 0, len(cfg.ExemptMounts))
	for _, m := range cfg.ExemptMounts {
		exempt = append(exempt, map[string]any{"mount": m.Mount, "mount_accessor": m.MountAccessor})
	}
	out := map[string]any{"unknown_aliases": cfg.UnknownAliases, "exempt_mounts": exempt}
	if len(cfg.Warnings) > 0 {
		out["warnings"] = cfg.Warnings
	}
	return helpers.RenderMap(out, func() {
		rows := [][]any{{"Unknown Aliases", cfg.UnknownAliases}}
		for i, m := range cfg.ExemptMounts {
			label := ""
			if i == 0 {
				label = "Exempt Mounts"
			}
			mount := m.Mount
			if mount == "" {
				mount = m.MountAccessor + " (mount gone)"
			}
			rows = append(rows, []any{label, mount})
		}
		helpers.PrintTable([]string{"Key", "Value"}, rows)
	})
}
