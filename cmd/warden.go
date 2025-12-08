package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/auth"
	"github.com/stephnangue/warden/cmd/basic"
	init_cmd "github.com/stephnangue/warden/cmd/init"
	"github.com/stephnangue/warden/cmd/login"
	"github.com/stephnangue/warden/cmd/providers"
	"github.com/stephnangue/warden/cmd/revoke"
	"github.com/stephnangue/warden/cmd/server"
)

var (
	wardenCmd = &cobra.Command{
		Use:   "warden",
		Short: "Warden is an identity-aware access fabric for cloud APIs",
		Long: `Warden eliminates cloud credentials and enforces Zero Trust for every cloud API call.
It acts as an authorization proxy for humans, machines, and AI, ensuring least privilege, 
safe operations, and complete visibility.`,
	}
)

func Execute() {
	if err := wardenCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	wardenCmd.AddCommand(server.ServerCmd)
	wardenCmd.AddCommand(init_cmd.InitCmd)
	wardenCmd.AddCommand(login.LoginCmd)
	wardenCmd.AddCommand(providers.ProvidersCmd)
	wardenCmd.AddCommand(auth.AuthCmd)
	wardenCmd.AddCommand(basic.WriteCmd)
	wardenCmd.AddCommand(revoke.RevokeRootTokenCmd)
}
