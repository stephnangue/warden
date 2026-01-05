package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/auth"
	"github.com/stephnangue/warden/cmd/basic"
	"github.com/stephnangue/warden/cmd/cred"
	"github.com/stephnangue/warden/cmd/login"
	"github.com/stephnangue/warden/cmd/namespaces"
	"github.com/stephnangue/warden/cmd/operator"
	"github.com/stephnangue/warden/cmd/providers"
	"github.com/stephnangue/warden/cmd/revoke"
	"github.com/stephnangue/warden/cmd/server"
)

var (
	// Global flag for namespace
	flagNamespace string

	wardenCmd = &cobra.Command{
		Use:   "warden",
		Short: "Warden is an identity-aware access fabric for cloud APIs",
		Long: `Warden eliminates cloud credentials and enforces Zero Trust for every cloud API call.
It acts as an authorization proxy for humans, machines, and AI, ensuring least privilege,
safe operations, and complete visibility.`,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			// Set the namespace in the environment if provided via flag
			if flagNamespace != "" {
				os.Setenv("WARDEN_NAMESPACE", flagNamespace)
			}
		},
	}
)

func Execute() {
	if err := wardenCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	// Add global namespace flag to the root command
	wardenCmd.PersistentFlags().StringVarP(&flagNamespace, "namespace", "n", "", "Warden namespace to use for the command (can also use WARDEN_NAMESPACE env var)")

	wardenCmd.AddCommand(server.ServerCmd)
	wardenCmd.AddCommand(operator.OperatorCmd)
	wardenCmd.AddCommand(login.LoginCmd)
	wardenCmd.AddCommand(providers.ProvidersCmd)
	wardenCmd.AddCommand(auth.AuthCmd)
	wardenCmd.AddCommand(namespaces.NamespacesCmd)
	wardenCmd.AddCommand(cred.CredCmd)
	wardenCmd.AddCommand(basic.WriteCmd)
	wardenCmd.AddCommand(revoke.RevokeRootTokenCmd)
}

// Namespace returns the currently configured namespace from the flag
func Namespace() string {
	return flagNamespace
}
