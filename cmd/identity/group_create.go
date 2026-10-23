package identity

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	createFlags groupFlags
	createJSON  string

	GroupCreateCmd = &cobra.Command{
		Use:           "create <name>",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Create a group in the current namespace (sudo)",
		Long: `
Usage: warden identity group create <name> [options]

  Create a group. "type" is required and never changes; "virtual" is the
  one type today. A virtual group's members are the callers whose verified
  facts match any one of its rules; membership grants the group's roles.
  Requires a token with sudo on sys/identity/group.

  A rule is a set of selectors, each a fact name with the values it may
  take; a caller must match one value of every selector. Every rule must
  include a "mount" selector: the auth mounts it trusts. Its other
  selectors name facts those mounts verify (built-in, or mapped in the
  mount's "facts"). "*" and "?" are globs ("*" stops at "/", "**" does
  not); a "mount" value holding "**" trusts mounts enabled later and is
  accepted with a warning. A role that does not exist yet, or a fact none
  of the listed mounts produces, is accepted with a warning on stderr.

  A namespace's virtual groups, and the selectors across all their rules
  ("mount" included), are capped; a write past either cap is refused with
  the current usage. 'warden identity usage' shows the usage and the caps.

  "valid_until" (RFC 3339) ends the group: it grants through that instant
  and nothing after, on the first request past it, even for callers whose
  admission Warden still holds; another group may still grant the same
  role. A time in the past is accepted with a warning. How old a caller's
  credential may be is not the group's to say: it is an admission bound
  of the auth mount.

  Two input modes (mutually exclusive):

    Full JSON payload (agent-friendly):

      $ warden identity group create ci-deployers -json '{
          "type": "virtual",
          "description": "CI deployers from GitHub and the ci cluster",
          "roles": ["deploy", "read-secrets"],
          "rules": [
            {
              "mount": ["auth/github-oidc/"],
              "repo": ["acme/*"],
              "ref": ["refs/heads/main"]
            },
            {
              "mount": ["auth/kubernetes/", "auth/spiffe/"],
              "workload": [
                "system:serviceaccount:ci:deployer",
                "spiffe://corp.example/ns/ci/sa/deployer"
              ]
            }
          ],
          "valid_until": "2026-12-31T23:59:59Z",
          "metadata": {
            "owner": "platform"
          }
        }'

      $ warden identity group create ci-deployers -json @ci-deployers.json
      $ cat ci-deployers.json | warden identity group create ci-deployers -json -

    Typed flags (human-friendly), one -rule per rule:

      $ warden identity group create ci-deployers \
          -type=virtual \
          -roles=deploy \
          -rule='{"mount": ["auth/kubernetes/"], "service_account_namespace": ["ci"]}' \
          -valid-until=2026-12-31T23:59:59Z

  Combine with -dry-run to validate the payload locally without creating
  the group.
`,
		Args: cobra.ExactArgs(1),
		RunE: runGroupCreate,
	}
)

func init() {
	createFlags.bind(GroupCreateCmd)
	GroupCreateCmd.Flags().StringVarP(&createJSON, "json", "j", "",
		"Full JSON payload — '<json>', '@file.json', or '-' for stdin (mutually exclusive with the typed flags)")
}

func runGroupCreate(cmd *cobra.Command, args []string) error {
	name := args[0]
	if err := validateGroupName(name); err != nil {
		return err
	}

	payload, err := helpers.ResolveJSONInput(createJSON)
	if err != nil {
		return err
	}
	if payload != nil {
		if err := helpers.RejectFlagsWithJSON(true, createFlags.changed(cmd)); err != nil {
			return err
		}
	} else {
		if payload, err = createFlags.payload(cmd); err != nil {
			return err
		}
	}

	c, err := helpers.Client()
	if err != nil {
		return err
	}
	if helpers.ResolveDryRun() {
		return helpers.DryRun(c, "POST", "sys/identity/group/{name}", payload)
	}

	resource, err := c.Operator().Post("sys/identity/group/"+name, payload)
	if err != nil {
		return fmt.Errorf("error creating group %q: %w", name, err)
	}
	return renderGroupWrite(resource, name, "created")
}
