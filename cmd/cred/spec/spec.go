package spec

import "github.com/spf13/cobra"

var SpecCmd = &cobra.Command{
	Use:   "spec",
	Short: "Manage credential specifications",
	Long:  `This command groups subcommands for managing Warden's credential specifications.`,
}

func init() {
	SpecCmd.AddCommand(CreateCmd)
	SpecCmd.AddCommand(ListCmd)
	SpecCmd.AddCommand(ReadCmd)
	SpecCmd.AddCommand(UpdateCmd)
	SpecCmd.AddCommand(DeleteCmd)
}
