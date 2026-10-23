package identity

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var GroupReadCmd = &cobra.Command{
	Use:           "read <name>",
	SilenceUsage:  true,
	SilenceErrors: true,
	Short:         "Read a group of the current namespace (sudo)",
	Long: `
Usage: warden identity group read <name>

  Read one group: its type, the roles it grants, its rules (one line each,
  a selector at a time: "#i  mount=…  name=v1|v2"), its rule and selector
  counts (what it adds to the namespace's usage), valid_until, metadata, and
  the hash a conditional update or delete passes back. Requires a token
  with sudo on sys/identity/group.

  Examples:

      $ warden identity group read ci-deployers
      $ warden identity group read ci-deployers -o json
      $ warden identity group read ci-deployers -fields hash
`,
	Args: cobra.ExactArgs(1),
	RunE: runGroupRead,
}

func runGroupRead(cmd *cobra.Command, args []string) error {
	name := args[0]
	if err := validateGroupName(name); err != nil {
		return err
	}

	c, err := helpers.Client()
	if err != nil {
		return err
	}
	resource, err := c.Operator().Read("sys/identity/group/" + name)
	if err != nil {
		return fmt.Errorf("error reading group %q: %w", name, err)
	}
	if resource == nil || resource.Data == nil {
		return fmt.Errorf("group %q not found: %w", name, helpers.ErrNotFound)
	}
	return helpers.RenderMap(resource.Data, func() {
		printGroupTable(resource.Data)
	})
}
