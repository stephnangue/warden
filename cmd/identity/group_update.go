package identity

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	updateFlags        groupFlags
	updateJSON         string
	updateExpectedHash string

	GroupUpdateCmd = &cobra.Command{
		Use:           "update <name>",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Update a group in the current namespace (sudo)",
		Long: `
Usage: warden identity group update <name> [options]

  Update a group. A field you pass replaces the stored value, including
  with an empty one ("roles": [] stops the group granting anything); a
  field you leave out keeps its value. "rules" is replaced whole.
  "type" may be left out; if present it must equal the stored type. The
  change applies to callers on their next request. Requires a token with
  sudo on sys/identity/group.

  Pass the hash from 'warden identity group read' as expected_hash to
  apply the update only if nobody changed the group since you read it;
  otherwise the server answers 409 and you read again.

  Two input modes (mutually exclusive):

    Full JSON payload (agent-friendly):

      $ warden identity group update ci-deployers -json '{
          "rules": [
            {
              "mount": ["auth/github-oidc/"],
              "repo": ["acme/infra"],
              "ref": ["refs/heads/main"]
            }
          ],
          "expected_hash": "<hash from warden identity group read>"
        }'

      $ warden identity group update ci-deployers -json @patch.json

    Typed flags (human-friendly):

      $ warden identity group update ci-deployers -roles=deploy,read-secrets
      $ warden identity group update ci-deployers -roles=""
      $ warden identity group update ci-deployers -valid-until=2026-12-31T23:59:59Z
      $ warden identity group update ci-deployers -valid-until=""
      $ warden identity group update ci-deployers \
          -rule='{"mount": ["auth/kubernetes/"], "workload": ["ci"]}'

  Combine with -dry-run to validate the payload locally without sending
  it.
`,
		Args: cobra.ExactArgs(1),
		RunE: runGroupUpdate,
	}
)

func init() {
	updateFlags.bind(GroupUpdateCmd)
	GroupUpdateCmd.Flags().StringVar(&updateExpectedHash, "expected-hash", "",
		"Apply the update only if the group still has this hash (from 'warden identity group read')")
	GroupUpdateCmd.Flags().StringVarP(&updateJSON, "json", "j", "",
		"Full JSON payload — '<json>', '@file.json', or '-' for stdin (mutually exclusive with the typed flags)")
}

func runGroupUpdate(cmd *cobra.Command, args []string) error {
	name := args[0]
	if err := validateGroupName(name); err != nil {
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
		if payload, err = updateFlags.payload(cmd); err != nil {
			return err
		}
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
		return helpers.DryRun(c, "PUT", "sys/identity/group/{name}", payload)
	}

	resource, err := c.Operator().Write("sys/identity/group/"+name, payload)
	if err != nil {
		return fmt.Errorf("error updating group %q: %w", name, err)
	}
	return renderGroupWrite(resource, name, "updated")
}
