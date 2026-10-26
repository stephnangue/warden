package identity

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	aliasAddFlags  aliasFlags
	aliasMoveFlags aliasFlags

	claimCommand = aliasCommand{entityKey: "to"}

	AliasAddCmd = &cobra.Command{
		Use:           "add",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Claim a native identity for an entity (sudo)",
		Long: `
Usage: warden identity alias add [options]

  Claim a native identity for an entity: the identity "name" presented
  through the auth mount "mount", as the mount derives it from a
  credential (its alias_name_source). A native identity is claimed by one
  entity in a namespace; one another entity claims is refused (use
  'warden identity alias move'), unless that entity is retired. A mount
  admitting humans cannot be claimed by an agent. Requires a token with
  sudo on sys/identity/entity.

      $ warden identity alias add -json '{
          "mount": "auth/jwt/",
          "name": "repo:corp/billing-agent:ref:refs/heads/main",
          "to": "billing-agent"
        }'

      $ warden identity alias add \
          -mount=auth/kubernetes/ \
          -name=system:serviceaccount:billing:agent \
          -to=billing-agent
`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error { return runAliasClaim(cmd, &aliasAddFlags, false) },
	}

	AliasMoveCmd = &cobra.Command{
		Use:           "move",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Move a native identity to another entity (sudo)",
		Long: `
Usage: warden identity alias move [options]

  Claim a native identity for an entity, taking it from the entity that
  claims it now, if any. The entity it was taken from is named in the
  output. Requires a token with sudo on sys/identity/entity.

      $ warden identity alias move -json '{
          "mount": "auth/cert/",
          "name": "spiffe://corp.example/billing-agent",
          "to": "invoice-agent"
        }'

      $ warden identity alias move -mount=auth/jwt/ -name=repo:corp/x -to=invoice-agent
`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error { return runAliasClaim(cmd, &aliasMoveFlags, true) },
	}
)

func init() {
	aliasAddFlags.bind(AliasAddCmd, claimCommand)
	aliasMoveFlags.bind(AliasMoveCmd, claimCommand)
}

func runAliasClaim(cmd *cobra.Command, f *aliasFlags, move bool) error {
	ref, entity, err := f.input(cmd, claimCommand)
	if err != nil {
		return err
	}

	c, err := helpers.Client()
	if err != nil {
		return err
	}
	if helpers.ResolveDryRun() {
		body := ref.Body()
		if move {
			body["move"] = true
		}
		return helpers.DryRun(c, "POST", "sys/identity/entity/{entity}/alias", body)
	}

	claim, err := c.Sys().ClaimAlias(entity, ref, move)
	if err != nil {
		return fmt.Errorf("error claiming native identity %q on %s for entity %q: %w", ref.Name, ref.Mount, entity, err)
	}
	out := map[string]any{
		"entity":         claim.Entity,
		"mount":          claim.Mount,
		"mount_accessor": claim.MountAccessor,
		"name":           claim.Name,
		"claimed":        true,
	}
	if claim.MovedFrom != "" {
		out["moved_from"] = claim.MovedFrom
	}
	return helpers.RenderMap(out, func() {
		msg := fmt.Sprintf("Success! Native identity %q on %s is claimed by entity %s", claim.Name, claim.Mount, claim.Entity)
		if claim.MovedFrom != "" {
			msg += fmt.Sprintf(" (taken from %s)", claim.MovedFrom)
		}
		fmt.Println(msg)
	})
}
