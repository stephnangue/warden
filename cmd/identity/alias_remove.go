package identity

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	aliasRemoveFlags aliasFlags

	releaseCommand = aliasCommand{entityKey: "from", byAccessor: true}

	AliasRemoveCmd = &cobra.Command{
		Use:           "remove",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Release a native identity from its entity (sudo)",
		Long: `
Usage: warden identity alias remove [options]

  Release a native identity from the entity "from": it is unclaimed again.
  If "from" does not claim it, nothing changes and the server answers that
  it is not claimed; 'warden identity entity lookup' names the entity that
  does. The mount is named by path, or by accessor ("mount_accessor"),
  which also names a mount disabled since ('warden identity entity list
  -orphaned'). A retired entity keeps its native identities: move them
  instead. Requires a token with sudo on sys/identity/entity.

      $ warden identity alias remove -json '{
          "mount": "auth/jwt/",
          "name": "repo:corp/billing-agent:ref:refs/heads/main",
          "from": "billing-agent"
        }'

      $ warden identity alias remove \
          -mount-accessor=jwt_8f3a2c1d \
          -name=repo:corp/billing-agent:ref:refs/heads/main \
          -from=billing-agent
`,
		Args: cobra.NoArgs,
		RunE: runAliasRemove,
	}
)

func init() {
	aliasRemoveFlags.bind(AliasRemoveCmd, releaseCommand)
}

func runAliasRemove(cmd *cobra.Command, args []string) error {
	ref, entity, err := aliasRemoveFlags.input(cmd, releaseCommand)
	if err != nil {
		return err
	}

	c, err := helpers.Client()
	if err != nil {
		return err
	}
	if helpers.ResolveDryRun() {
		return helpers.DryRun(c, "POST", "sys/identity/entity/{entity}/alias/remove", ref.Body())
	}

	if err := c.Sys().RemoveAlias(entity, ref); err != nil {
		return fmt.Errorf("error releasing native identity %q on %s from entity %q: %w",
			ref.Name, aliasMountLabel(ref), entity, err)
	}
	return helpers.RenderMap(map[string]any{
		"entity":         entity,
		"mount":          ref.Mount,
		"mount_accessor": ref.MountAccessor,
		"name":           ref.Name,
		"released":       true,
	}, func() {
		fmt.Printf("Success! Released native identity %q on %s from entity %s\n", ref.Name, aliasMountLabel(ref), entity)
	})
}
