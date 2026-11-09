package roles

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	updateFlags        roleFlags
	updateJSON         string
	updateExpectedHash string

	UpdateCmd = &cobra.Command{
		Use:           "update <name>",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Update a role in the current namespace (sudo)",
		Long: `
Usage: warden role update <name> [options]

  Update a role. A field you pass replaces the stored value, including
  with an empty one ("policies": [] clears the policies); a field you
  leave out keeps its value. Requires a token with sudo on sys/roles.

  Pass the hash from 'warden role read' as expected_hash to apply the
  update only if nobody changed the role since you read it; otherwise the
  server answers 409 and you read again.

  Two input modes (mutually exclusive):

    Full JSON payload (agent-friendly):

      $ warden role update deploy -json '{
          "policies": ["deploy", "audit-read"],
          "expected_hash": "<hash from warden role read>"
        }'

      $ warden role update deploy -json @patch.json

    Typed flags (human-friendly):

      $ warden role update deploy -policies=deploy,audit-read
      $ warden role update deploy -cred-spec-name=""

  Combine with -dry-run to validate the payload locally without sending
  it.
`,
		Args: cobra.ExactArgs(1),
		RunE: runUpdate,
	}
)

func init() {
	updateFlags.bind(UpdateCmd)
	UpdateCmd.Flags().StringVar(&updateExpectedHash, "expected-hash", "",
		"Apply the update only if the role still has this hash (from 'warden role read')")
	UpdateCmd.Flags().StringVarP(&updateJSON, "json", "j", "",
		"Full JSON payload — '<json>', '@file.json', or '-' for stdin (mutually exclusive with the typed flags)")
}

func runUpdate(cmd *cobra.Command, args []string) error {
	name := args[0]
	if err := validateRoleName(name); err != nil {
		return err
	}

	payload, err := helpers.ResolveJSONInput(updateJSON)
	if err != nil {
		return err
	}
	if payload != nil {
		flags := updateFlags.changed(cmd)
		flags["-expected-hash"] = updateExpectedHash != ""
		if err := helpers.RejectFlagsWithJSON(true, flags); err != nil {
			return err
		}
	} else {
		payload = updateFlags.payload(cmd)
		if len(payload) == 0 {
			return fmt.Errorf("no fields to update: pass at least one flag or use -json: %w", helpers.ErrUsage)
		}
		if updateExpectedHash != "" {
			payload["expected_hash"] = updateExpectedHash
		}
	}

	c, err := helpers.Client()
	if err != nil {
		return err
	}
	if helpers.ResolveDryRun() {
		return helpers.DryRun(c, "PUT", "sys/roles/{name}", payload)
	}

	resource, err := c.Operator().Write("sys/roles/"+name, payload)
	if err != nil {
		return fmt.Errorf("error updating role %q: %w", name, err)
	}
	return renderRoleWrite(resource, name, "updated")
}
