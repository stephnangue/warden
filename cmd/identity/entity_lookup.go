package identity

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	entityLookupFlags aliasFlags

	lookupCommand = aliasCommand{byAccessor: true}

	EntityLookupCmd = &cobra.Command{
		Use:           "lookup",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Look up the entity that claims a native identity (sudo)",
		Long: `
Usage: warden identity entity lookup [options]

  Answer which entity claims the native identity "name" presented through
  the auth mount "mount" (by path, or by accessor with "mount_accessor"):
  its name, ID, kind, state and governed_by. An unclaimed native identity
  is not found. Requires a token with sudo on sys/identity/lookup.

      $ warden identity entity lookup -json '{
          "mount": "auth/kubernetes/",
          "name": "system:serviceaccount:billing:agent"
        }'

      $ warden identity entity lookup \
          -mount=auth/jwt/ \
          -name=repo:corp/billing-agent:ref:refs/heads/main

      $ warden identity entity lookup -mount=auth/jwt/ -name=repo:corp/x -o json | jq -r .entity
`,
		Args: cobra.NoArgs,
		RunE: runEntityLookup,
	}
)

func init() {
	entityLookupFlags.bind(EntityLookupCmd, lookupCommand)
}

func runEntityLookup(cmd *cobra.Command, args []string) error {
	ref, _, err := entityLookupFlags.input(cmd, lookupCommand)
	if err != nil {
		return err
	}

	c, err := helpers.Client()
	if err != nil {
		return err
	}
	if helpers.ResolveDryRun() {
		return helpers.DryRun(c, "POST", "sys/identity/lookup", ref.Body())
	}

	l, err := c.Sys().LookupAlias(ref)
	if err != nil {
		return fmt.Errorf("error looking up native identity %q on %s: %w", ref.Name, aliasMountLabel(ref), err)
	}
	out := map[string]any{
		"entity":      l.Entity,
		"entity_id":   l.EntityID,
		"kind":        l.Kind,
		"state":       l.State,
		"governed_by": l.GovernedBy,
	}
	return helpers.RenderMap(out, func() {
		governed := l.GovernedBy
		if governed == "" {
			governed = "(ungoverned)"
		}
		helpers.PrintTable([]string{"Key", "Value"}, [][]any{
			{"Entity", l.Entity},
			{"Entity ID", l.EntityID},
			{"Kind", l.Kind},
			{"State", l.State},
			{"Governed By", governed},
		})
	})
}
