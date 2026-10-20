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

  A namespace holds at most 8000 groups and 16000 selectors across all
  their rules ("mount" included); a write past either is refused with the
  current usage.

  "max_age" bounds how old the caller's credential may be, counted from
  when it was issued (its "iat"), on every request. With "max_age": "10m",
  a CI token issued at 12:00:00 is a member through 12:10:00 and stops
  being one right after, even while Warden still holds its admission;
  another group without max_age may still grant the same role. A
  credential that carries no issue time (a client certificate, an
  X.509-SVID) never satisfies a group with max_age.

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
          "max_age": "10m",
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
          -max-age=10m

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
