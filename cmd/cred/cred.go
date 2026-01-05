package cred

import (
	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/cred/source"
	"github.com/stephnangue/warden/cmd/cred/spec"
)

var CredCmd = &cobra.Command{
	Use:   "cred",
	Short: "Manage credentials",
	Long:  `This command groups subcommands for managing Warden's credential specs and sources.`,
}

func init() {
	CredCmd.AddCommand(spec.SpecCmd)
	CredCmd.AddCommand(source.SourceCmd)
}
