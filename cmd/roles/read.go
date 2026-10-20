package roles

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
)

// grantingGroups returns, for role (or every role when role is empty), the
// names of the groups that grant it, sorted, from one group listing: the
// server filters by role for one role, and the inventory inverts the full
// listing client-side rather than asking once per role.
func grantingGroups(c *api.Client, role string) (map[string][]string, error) {
	list, err := c.Sys().ListGroups(role)
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for _, g := range list.Groups {
		for _, r := range g.Roles {
			out[r] = append(out[r], g.Name)
		}
	}
	return out, nil
}

var ReadCmd = &cobra.Command{
	Use:           "read <name>",
	SilenceUsage:  true,
	SilenceErrors: true,
	Short:         "Read a role of the current namespace (sudo)",
	Long: `
Usage: warden role read <name>

  Read one role: its policies, credential spec, discovery fields,
  metadata, the groups that grant it ("granted_by"), and the hash a
  conditional update or delete passes back. Requires a token with sudo on
  sys/roles; listing the granting groups also needs sudo on
  sys/identity/group, and without it the role is shown alone with a
  warning.

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
	if grants, err := grantingGroups(c, name); err != nil {
		helpers.PrintWarnings([]string{fmt.Sprintf("cannot list the groups granting %q: %v", name, err)})
	} else {
		resource.Data["granted_by"] = stringsToAny(grants[name])
	}
	return helpers.RenderMap(resource.Data, func() {
		printRoleTable(resource.Data)
	})
}
