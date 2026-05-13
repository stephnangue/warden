// Package skills groups the CLI subcommands for the global agent skill
// registry exposed at /v1/sys/skills. Reads are open to any namespace
// token; mutations are root-only — invoking create/update/delete from a
// sub-namespace surfaces the server's 403.
package skills

import "github.com/spf13/cobra"

var SkillsCmd = &cobra.Command{
	Use:   "skill",
	Short: "Manage agent skills served from the global skill registry.",
	Long: `
Usage: warden skill <subcommand> [options]

  Browse and manage the global agent skill registry. Skills are the
  agent-facing recipes that describe how to use Warden's capabilities
  (the foundation flow plus one record per provider type). Reads are
  open to any namespace; writes are restricted to the root namespace.

  List every skill in the catalog:

      $ warden skill list

  Read one skill's full markdown body:

      $ warden skill read aws --raw

  Create a custom skill (root namespace only):

      $ warden skill create --name=my-runbook --category=custom \
          --description="ops on-call" --body-file=./runbook.md

  Please see the individual subcommand help for detailed usage information.
`,
}

func init() {
	SkillsCmd.AddCommand(ListCmd)
	SkillsCmd.AddCommand(ReadCmd)
	SkillsCmd.AddCommand(CreateCmd)
	SkillsCmd.AddCommand(UpdateCmd)
	SkillsCmd.AddCommand(DeleteCmd)
}
