package identity

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	entityUpdateFlags        entityFlags
	entityUpdateJSON         string
	entityUpdateExpectedHash string

	EntityUpdateCmd = &cobra.Command{
		Use:           "update <name>",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Update an entity in the current namespace (sudo)",
		Long: `
Usage: warden identity entity update <name> [options]

  Update an entity's description, profile and metadata. A field you pass
  replaces the stored value, including with an empty one (an empty
  description leaves the entity ungoverned); a field you leave out keeps
  its value. "new_name" renames it; its ID does not change. The kind never
  changes; the native identities change through 'warden identity alias',
  the sponsor through 'warden identity entity sponsor', and the state
  through 'warden identity entity state'. Requires a token with sudo on
  sys/identity/entity.

  Pass the hash from 'warden identity entity read' as expected_hash to
  apply the update only if nobody changed the entity since you read it;
  otherwise the server answers 409 and you read again.

  Two input modes (mutually exclusive):

    Full JSON payload (agent-friendly):

      $ warden identity entity update ci-runner -json '{
          "description": "Builds and deploys the billing service",
          "metadata": {
            "team": "billing"
          }
        }'

    Typed flags (human-friendly):

      $ warden identity entity update billing-agent -description="Reconciles supplier invoices"
      $ warden identity entity update billing-agent -new-name=invoice-agent

  Combine with -dry-run to validate the payload locally without sending
  it.
`,
		Args: cobra.ExactArgs(1),
		RunE: runEntityUpdate,
	}
)

func init() {
	entityUpdateFlags.bind(EntityUpdateCmd, false)
	EntityUpdateCmd.Flags().StringVar(&entityUpdateExpectedHash, "expected-hash", "",
		"Apply the update only if the entity still has this hash (from 'warden identity entity read')")
	EntityUpdateCmd.Flags().StringVarP(&entityUpdateJSON, "json", "j", "",
		"Full JSON payload — '<json>', '@file.json', or '-' for stdin (mutually exclusive with the typed flags)")
}

func runEntityUpdate(cmd *cobra.Command, args []string) error {
	name := args[0]
	if err := validateEntityName(name); err != nil {
		return err
	}

	payload, err := helpers.ResolveJSONInput(entityUpdateJSON)
	if err != nil {
		return err
	}
	if payload != nil {
		flags := entityUpdateFlags.changed(cmd)
		flags["-expected-hash"] = entityUpdateExpectedHash != ""
		if err := helpers.RejectFlagsWithJSON(true, flags); err != nil {
			return err
		}
	} else {
		if payload, err = entityUpdateFlags.payload(cmd); err != nil {
			return err
		}
		if len(payload) == 0 {
			return fmt.Errorf("no fields to update: pass at least one flag or use -json: %w", helpers.ErrUsage)
		}
		if entityUpdateExpectedHash != "" {
			payload["expected_hash"] = entityUpdateExpectedHash
		}
	}

	c, err := helpers.Client()
	if err != nil {
		return err
	}
	if helpers.ResolveDryRun() {
		return helpers.DryRun(c, "PUT", "sys/identity/entity/{name}", payload)
	}

	resource, err := c.Operator().Write("sys/identity/entity/"+name, payload)
	if err != nil {
		return fmt.Errorf("error updating entity %q: %w", name, err)
	}
	if renamed, _ := payload["new_name"].(string); renamed != "" {
		name = renamed
	}
	return renderEntityWrite(resource, name, "updated")
}
