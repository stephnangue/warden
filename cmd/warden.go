package cmd

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/audit"
	"github.com/stephnangue/warden/cmd/auth"
	"github.com/stephnangue/warden/cmd/basic"
	"github.com/stephnangue/warden/cmd/cred"
	"github.com/stephnangue/warden/cmd/helpers"
	"github.com/stephnangue/warden/cmd/namespaces"
	"github.com/stephnangue/warden/cmd/operator"
	"github.com/stephnangue/warden/cmd/policies"
	"github.com/stephnangue/warden/cmd/providers"
	"github.com/stephnangue/warden/cmd/roles"
	"github.com/stephnangue/warden/cmd/schema"
	"github.com/stephnangue/warden/cmd/server"
	"github.com/stephnangue/warden/cmd/skills"
	"github.com/stephnangue/warden/cmd/status"
)

var (
	// Global flags
	flagNamespace string
	flagRole      string

	wardenCmd = &cobra.Command{
		Use:   "warden",
		Short: "Warden is an identity-aware access fabric for cloud APIs",
		Long: `Warden eliminates cloud credentials and enforces Zero Trust for every cloud API call.
It acts as an authorization proxy for humans, machines, and AI, ensuring least privilege,
safe operations, and complete visibility.`,
		// Silence Cobra's default error/usage printing so the central renderer
		// in Execute() is the only thing that writes to stderr on failure.
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if err := helpers.ValidateHeaderValue("--namespace", flagNamespace); err != nil {
				return err
			}
			if err := helpers.ValidateHeaderValue("--role", flagRole); err != nil {
				return err
			}
			if flagNamespace != "" {
				os.Setenv("WARDEN_NAMESPACE", flagNamespace)
			}
			if flagRole != "" {
				os.Setenv("WARDEN_ROLE", flagRole)
			}
			return nil
		},
	}
)

func Execute() {
	wardenCmd.SetArgs(helpers.NormalizeSingleDashFlags(wardenCmd, os.Args[1:]))
	if err := wardenCmd.Execute(); err != nil {
		os.Exit(int(helpers.RenderError(err)))
	}
}

func init() {
	wardenCmd.PersistentFlags().StringVarP(&flagNamespace, "namespace", "n", "", "Warden namespace to use for the command (can also use WARDEN_NAMESPACE env var)")
	wardenCmd.PersistentFlags().StringVarP(&flagRole, "role", "r", "", "Warden role to use for the command (can also use WARDEN_ROLE env var)")
	wardenCmd.PersistentFlags().StringVarP(helpers.OutputFlagPtr(), "output", "o", "", "Output format: table, json, ndjson, text. Defaults to table on a TTY, json otherwise. Honors WARDEN_OUTPUT.")
	wardenCmd.PersistentFlags().StringVarP(helpers.FieldsFlagPtr(), "fields", "F", "", "Comma-separated dot-paths to project from structured output (e.g. name,metadata.created_at,tokens.*.id). Honors WARDEN_FIELDS.")
	wardenCmd.PersistentFlags().BoolVarP(helpers.DryRunFlagPtr(), "dry-run", "D", false, "Send X-Warden-Dry-Run on every request so the server validates without mutating. Honors WARDEN_DRY_RUN. Server enforcement is not yet shipped — see CHANGELOG.")

	wardenCmd.AddCommand(server.ServerCmd)
	wardenCmd.AddCommand(status.StatusCmd)
	wardenCmd.AddCommand(operator.OperatorCmd)
	wardenCmd.AddCommand(providers.ProvidersCmd)
	wardenCmd.AddCommand(auth.AuthCmd)
	wardenCmd.AddCommand(audit.AuditCmd)
	wardenCmd.AddCommand(namespaces.NamespacesCmd)
	wardenCmd.AddCommand(policies.PoliciesCmd)
	wardenCmd.AddCommand(cred.CredCmd)
	wardenCmd.AddCommand(schema.SchemaCmd)
	wardenCmd.AddCommand(roles.RolesCmd)
	wardenCmd.AddCommand(skills.SkillsCmd)
	wardenCmd.AddCommand(basic.WriteCmd)
	wardenCmd.AddCommand(basic.ReadCmd)
	wardenCmd.AddCommand(basic.ListCmd)
	wardenCmd.AddCommand(basic.DeleteCmd)
	wardenCmd.AddCommand(basic.PathHelpCmd)
}

// serverVersion holds the binary's build version once SetVersion has been
// called. It's read by cmd/server when constructing the HTTP handler so the
// /v1/sys/health response can surface it.
var serverVersion string

// SetVersion sets the version string on the root command.
// Called from main with the value injected via ldflags.
func SetVersion(v string) {
	wardenCmd.Version = v
	serverVersion = v
	server.SetBuildVersion(v)
}

// Version returns the build version previously set via SetVersion.
func Version() string {
	return serverVersion
}

// Namespace returns the currently configured namespace from the flag
func Namespace() string {
	return flagNamespace
}
