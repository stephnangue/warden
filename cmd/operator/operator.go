package operator

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	OperatorCmd = &cobra.Command{
		Use:   "operator",
		Short: "Perform administrative operations on Warden",
		Long: `The operator command provides administrative operations for managing Warden.

This includes system initialization, seal/unseal operations, and other
operational tasks required to maintain and manage a Warden server.

Available subcommands:
  - init: Initialize Warden and generate root token

Usage:
  $ warden operator <subcommand> [options]

Examples:
  $ warden operator init
`,
	}
)

func Execute() {
	if err := OperatorCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	OperatorCmd.AddCommand(initCmd)
}