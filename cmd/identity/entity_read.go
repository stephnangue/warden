package identity

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var entityReadID string

var EntityReadCmd = &cobra.Command{
	Use:           "read [<name>]",
	SilenceUsage:  true,
	SilenceErrors: true,
	Short:         "Read an entity of the current namespace (sudo)",
	Long: `
Usage: warden identity entity read <name>
       warden identity entity read -id <id>

  Read one entity, by name or by ID (which never changes): its kind and
  state, governed_by (or why it is ungoverned), its sponsor and any pending
  handover (the group, and who accepted or proposed it), profile,
  metadata, the native identities it claims (one line each, "<mount>
  <name>"; a mount disabled since shows by accessor), and the hash a
  conditional write passes back. Requires a token with sudo on
  sys/identity/entity.

  Examples:

      $ warden identity entity read billing-agent
      $ warden identity entity read -id 6f1c0d2e-…
      $ warden identity entity read billing-agent -o json
      $ warden identity entity read billing-agent -fields hash
`,
	Args: cobra.MaximumNArgs(1),
	RunE: runEntityRead,
}

func init() {
	EntityReadCmd.Flags().StringVar(&entityReadID, "id", "", "Read the entity with this ID instead of by name")
}

func runEntityRead(cmd *cobra.Command, args []string) error {
	var path, what string
	switch {
	case len(args) == 1 && entityReadID != "":
		return fmt.Errorf("pass a name or -id, not both: %w", helpers.ErrUsage)
	case len(args) == 1:
		if err := validateEntityName(args[0]); err != nil {
			return err
		}
		path, what = "sys/identity/entity/"+args[0], fmt.Sprintf("entity %q", args[0])
	case entityReadID != "":
		if err := helpers.ValidateIdentifier("entity id", entityReadID); err != nil {
			return err
		}
		path, what = "sys/identity/entity/id/"+entityReadID, fmt.Sprintf("entity with id %q", entityReadID)
	default:
		return fmt.Errorf("an entity name or -id is required: %w", helpers.ErrUsage)
	}

	c, err := helpers.Client()
	if err != nil {
		return err
	}
	resource, err := c.Operator().Read(path)
	if err != nil {
		return fmt.Errorf("error reading %s: %w", what, err)
	}
	if resource == nil || resource.Data == nil {
		return fmt.Errorf("%s not found: %w", what, helpers.ErrNotFound)
	}
	return helpers.RenderMap(resource.Data, func() {
		printEntityTable(resource.Data)
	})
}
