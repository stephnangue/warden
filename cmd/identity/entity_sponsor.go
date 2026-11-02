package identity

import (
	"fmt"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	sponsorProposeGroup        string
	sponsorProposeNamespace    string
	sponsorProposeExpectedHash string
	sponsorProposeJSON         string

	sponsorRemovePending      bool
	sponsorRemoveExpectedHash string

	EntitySponsorCmd = &cobra.Command{
		Use:   "sponsor",
		Short: "Propose or remove the sponsor of an entity (sudo)",
		Long: `
Usage: warden identity entity sponsor <subcommand> [options]

  An entity's sponsor is the team accountable for it: a virtual group of
  humans, of the entity's namespace or of one of its ancestors. An entity
  with an accepted sponsor and a description is governed.

  A proposal by a member of the group makes it the sponsor at once.
  Anyone else's proposal is a pending handover: the current sponsor stays
  until a member of the group accepts it, signed in with 'warden login'.

      $ warden -n team-a identity entity sponsor propose billing-agent -group billing-leads -group-namespace /
      $ warden identity entity sponsor remove billing-agent -pending
      $ warden identity entity sponsor remove billing-agent

  Please see the individual subcommand help for detailed usage information.
`,
	}

	EntitySponsorProposeCmd = &cobra.Command{
		Use:           "propose <entity>",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Propose a group as the sponsor of an entity (sudo)",
		Long: `
Usage: warden identity entity sponsor propose <entity> [options]

  Propose a virtual group of humans as the sponsor of an entity. The
  group is one of the entity's namespace (the request's, set with -n), or
  of an ancestor's with -group-namespace ("/" for the root namespace; the
  payload's "namespace"). When you are a member of the group the
  proposal is accepted at once and replaces the current sponsor in the
  same write; otherwise it is a pending handover (replacing any earlier
  one), which a member accepts. Root is a member of no group, so its
  proposals are always pending. Requires a token with sudo on
  sys/identity/entity.

      $ warden identity entity sponsor propose billing-agent -json '{
          "group": "billing-leads",
          "namespace": "/"
        }'

      $ warden identity entity sponsor propose billing-agent -group finance-oncall
`,
		Args: cobra.ExactArgs(1),
		RunE: runSponsorPropose,
	}

	EntitySponsorRemoveCmd = &cobra.Command{
		Use:           "remove <entity>",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Remove the sponsor of an entity, or cancel its pending handover (sudo)",
		Long: `
Usage: warden identity entity sponsor remove <entity> [options]

  Remove the sponsor of an entity: it is ungoverned until another is
  accepted. A pending handover stays, for a member of its group to
  accept. With -pending, cancel the pending handover instead. Requires a
  token with sudo on sys/identity/entity.

      $ warden identity entity sponsor remove billing-agent
      $ warden identity entity sponsor remove billing-agent -pending
`,
		Args: cobra.ExactArgs(1),
		RunE: runSponsorRemove,
	}
)

func init() {
	fs := EntitySponsorProposeCmd.Flags()
	fs.StringVar(&sponsorProposeGroup, "group", "", "The virtual group proposed as the sponsor, by name")
	// Not "-namespace": that is the global -n, the namespace of the request
	// and so of the entity.
	fs.StringVar(&sponsorProposeNamespace, "group-namespace", "",
		`The group's namespace: the entity's (the default) or an ancestor ("/" for the root namespace)`)
	fs.StringVar(&sponsorProposeExpectedHash, "expected-hash", "",
		"Propose only if the entity still has this hash (from 'warden identity entity read')")
	fs.StringVarP(&sponsorProposeJSON, "json", "j", "",
		"Full JSON payload — '<json>', '@file.json', or '-' for stdin (mutually exclusive with the typed flags)")

	fs = EntitySponsorRemoveCmd.Flags()
	fs.BoolVar(&sponsorRemovePending, "pending", false, "Cancel the pending handover instead of removing the sponsor")
	fs.StringVar(&sponsorRemoveExpectedHash, "expected-hash", "",
		"Remove only if the entity still has this hash (from 'warden identity entity read')")

	EntitySponsorCmd.AddCommand(EntitySponsorProposeCmd)
	EntitySponsorCmd.AddCommand(EntitySponsorRemoveCmd)
}

// proposeKeys are the fields of a proposal's -json payload.
var proposeKeys = []string{"group", "namespace", "expected_hash"}

func runSponsorPropose(cmd *cobra.Command, args []string) error {
	name := args[0]
	if err := validateEntityName(name); err != nil {
		return err
	}
	payload, err := helpers.ResolveJSONInput(sponsorProposeJSON)
	if err != nil {
		return err
	}
	if payload != nil {
		changed := map[string]bool{}
		for _, flag := range []string{"group", "group-namespace", "expected-hash"} {
			changed["-"+flag] = cmd.Flags().Changed(flag)
		}
		if err := helpers.RejectFlagsWithJSON(true, changed); err != nil {
			return err
		}
		for k, v := range payload {
			if !slices.Contains(proposeKeys, k) {
				return fmt.Errorf("unknown field %q: the payload takes %s: %w", k, strings.Join(proposeKeys, ", "), helpers.ErrUsage)
			}
			if _, ok := v.(string); !ok {
				return fmt.Errorf("%q must be a string: %w", k, helpers.ErrUsage)
			}
		}
	} else {
		payload = map[string]any{"group": sponsorProposeGroup}
		if sponsorProposeNamespace != "" {
			payload["namespace"] = sponsorProposeNamespace
		}
		if sponsorProposeExpectedHash != "" {
			payload["expected_hash"] = sponsorProposeExpectedHash
		}
	}
	if g, _ := payload["group"].(string); g == "" {
		return fmt.Errorf("group is required: %w", helpers.ErrUsage)
	}

	c, err := helpers.Client()
	if err != nil {
		return err
	}
	if helpers.ResolveDryRun() {
		return helpers.DryRun(c, "POST", "sys/identity/entity/{entity}/sponsor", payload)
	}
	resource, err := c.Operator().Post("sys/identity/entity/"+name+"/sponsor", payload)
	if err != nil {
		return fmt.Errorf("error proposing a sponsor for entity %q: %w", name, err)
	}
	return renderEntityWrite(resource, name, "proposed")
}

func runSponsorRemove(cmd *cobra.Command, args []string) error {
	name := args[0]
	if err := validateEntityName(name); err != nil {
		return err
	}
	payload := map[string]any{}
	if sponsorRemovePending {
		payload["pending"] = true
	}
	if sponsorRemoveExpectedHash != "" {
		payload["expected_hash"] = sponsorRemoveExpectedHash
	}

	c, err := helpers.Client()
	if err != nil {
		return err
	}
	if helpers.ResolveDryRun() {
		return helpers.DryRun(c, "POST", "sys/identity/entity/{entity}/sponsor/remove", payload)
	}
	resource, err := c.Operator().Post("sys/identity/entity/"+name+"/sponsor/remove", payload)
	if err != nil {
		what := "removing the sponsor of"
		if sponsorRemovePending {
			what = "cancelling the sponsor handover of"
		}
		return fmt.Errorf("error %s entity %q: %w", what, name, err)
	}
	return renderEntityWrite(resource, name, "updated")
}
