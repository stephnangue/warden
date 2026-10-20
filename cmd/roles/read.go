package roles

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var ReadCmd = &cobra.Command{
	Use:           "read <name>",
	SilenceUsage:  true,
	SilenceErrors: true,
	Short:         "Read a role of the current namespace (sudo)",
	Long: `
Usage: warden role read <name>

  Read one role: its policies, credential spec, discovery fields,
  metadata, and the hash a conditional update or delete passes back.
  Requires a token with sudo on sys/roles.

  Examples:

      $ warden role read deploy
      $ warden role read deploy -o json
      $ warden role read deploy -fields hash
`,
	Args: cobra.ExactArgs(1),
	RunE: runRead,
}

func runRead(cmd *cobra.Command, args []string) error {
	name := args[0]
	if err := validateRoleName(name); err != nil {
		return err
	}

	c, err := helpers.Client()
	if err != nil {
		return err
	}
	resource, err := c.Operator().Read("sys/roles/" + name)
	if err != nil {
		return fmt.Errorf("error reading role %q: %w", name, err)
	}
	if resource == nil || resource.Data == nil {
		return fmt.Errorf("role %q not found: %w", name, helpers.ErrNotFound)
	}
	return helpers.RenderMap(resource.Data, func() {
		printRoleTable(resource.Data)
	})
}
