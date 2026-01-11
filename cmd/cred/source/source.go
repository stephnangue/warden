package source

import "github.com/spf13/cobra"

var SourceCmd = &cobra.Command{
	Use:   "source",
	Short: "Manage credential sources",
	Long:  `This command groups subcommands for managing Warden's credential sources.`,
}

func init() {
	SourceCmd.AddCommand(CreateCmd)
	SourceCmd.AddCommand(ListCmd)
	SourceCmd.AddCommand(ReadCmd)
	SourceCmd.AddCommand(UpdateCmd)
	SourceCmd.AddCommand(DeleteCmd)
}
