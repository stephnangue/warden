package identity

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	sponsorHandoverGroup     string
	sponsorHandoverNamespace string
	sponsorHandoverCancel    bool

	SponsorCmd = &cobra.Command{
		Use:   "sponsor",
		Short: "Act on the entities your team sponsors (no role needed)",
		Long: `
Usage: warden identity sponsor <subcommand> <entity> [options]

  Act, as a member of an entity's sponsor group, on the entity your team
  stands behind: read it, suspend it, hand it over to another team, or
  accept one handed over to yours. No Warden role is needed: sign in
  with 'warden login'; your session's groups decide what you sponsor.

      $ warden identity sponsor read billing-agent
      $ warden identity sponsor suspend billing-agent
      $ warden -n team-a identity sponsor handover billing-agent -group finance-oncall -group-namespace /
      $ warden identity sponsor handover billing-agent -cancel
      $ warden identity sponsor accept billing-agent

  Every refusal reads "no sponsored agent by that name", whatever its
  cause. Making an entity active again, and removing its sponsor, are
  admin writes ('warden identity entity state', 'warden identity entity
  sponsor remove').
`,
	}

	SponsorReadCmd = &cobra.Command{
		Use:           "read <entity>",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Read an entity your team sponsors, or is offered",
		Long: `
Usage: warden identity sponsor read <entity>

  Read an entity as a member of its sponsor group, or of the group it is
  being handed over to, so you can see what you are asked to accept.

      $ warden identity sponsor read billing-agent
`,
		Args: cobra.ExactArgs(1),
		RunE: runSponsorRead,
	}

	SponsorSuspendCmd = &cobra.Command{
		Use:           "suspend <entity>",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Suspend an entity your team sponsors",
		Long: `
Usage: warden identity sponsor suspend <entity>

  Suspend an entity as a member of its sponsor group: its requests are
  refused until an admin makes it active again.

      $ warden identity sponsor suspend billing-agent
`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSponsorVerb(args[0], "suspend", map[string]any{}, "suspending")
		},
	}

	SponsorHandoverCmd = &cobra.Command{
		Use:           "handover <entity>",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Hand an entity your team sponsors over to another group",
		Long: `
Usage: warden identity sponsor handover <entity> -group <name> [-group-namespace <path>]
       warden identity sponsor handover <entity> -cancel

  Offer an entity your team sponsors to another virtual group of humans,
  of the entity's namespace (the request's, set with -n) or an
  ancestor's with -group-namespace ("/" for the root namespace). A
  member of that group accepts it; your team stays the
  sponsor until then. When you are a member of both, the handover is
  accepted at once. -cancel withdraws the pending handover.

      $ warden identity sponsor handover billing-agent -group finance-oncall -group-namespace /
      $ warden identity sponsor handover billing-agent -cancel
`,
		Args: cobra.ExactArgs(1),
		RunE: runSponsorHandover,
	}

	SponsorAcceptCmd = &cobra.Command{
		Use:           "accept <entity>",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Accept an entity handed over to your team",
		Long: `
Usage: warden identity sponsor accept <entity>

  Accept, as a member of the group an entity is being handed over to,
  that your team now sponsors it. It replaces the earlier sponsor in the
  same write.

      $ warden identity sponsor read billing-agent
      $ warden identity sponsor accept billing-agent
`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSponsorVerb(args[0], "accept", map[string]any{}, "accepting")
		},
	}
)

func init() {
	fs := SponsorHandoverCmd.Flags()
	fs.StringVar(&sponsorHandoverGroup, "group", "", "The virtual group the entity is handed over to")
	// Not "-namespace": that is the global -n, the namespace of the request
	// and so of the entity.
	fs.StringVar(&sponsorHandoverNamespace, "group-namespace", "",
		`The group's namespace: the entity's (the default) or an ancestor ("/" for the root namespace)`)
	fs.BoolVar(&sponsorHandoverCancel, "cancel", false, "Cancel the pending handover instead")

	SponsorCmd.AddCommand(SponsorReadCmd)
	SponsorCmd.AddCommand(SponsorSuspendCmd)
	SponsorCmd.AddCommand(SponsorHandoverCmd)
	SponsorCmd.AddCommand(SponsorAcceptCmd)
}

func runSponsorRead(cmd *cobra.Command, args []string) error {
	name := args[0]
	if err := validateEntityName(name); err != nil {
		return err
	}
	c, err := helpers.Client()
	if err != nil {
		return err
	}
	resource, err := c.Operator().Read("sys/identity/sponsor/" + name)
	if err != nil {
		return fmt.Errorf("error reading entity %q: %w", name, err)
	}
	if resource == nil || resource.Data == nil {
		return fmt.Errorf("entity %q not found: %w", name, helpers.ErrNotFound)
	}
	return helpers.RenderMap(resource.Data, func() {
		printEntityTable(resource.Data)
	})
}

func runSponsorHandover(cmd *cobra.Command, args []string) error {
	switch {
	case sponsorHandoverCancel && (sponsorHandoverGroup != "" || sponsorHandoverNamespace != ""):
		return fmt.Errorf("-cancel takes no -group or -group-namespace: %w", helpers.ErrUsage)
	case sponsorHandoverCancel:
		return runSponsorVerb(args[0], "handover", map[string]any{"cancel": true}, "cancelling the handover of")
	case sponsorHandoverGroup == "":
		return fmt.Errorf("-group is required, or -cancel: %w", helpers.ErrUsage)
	}
	body := map[string]any{"group": sponsorHandoverGroup}
	if sponsorHandoverNamespace != "" {
		body["namespace"] = sponsorHandoverNamespace
	}
	return runSponsorVerb(args[0], "handover", body, "handing over")
}

// runSponsorVerb posts body to the sponsor path verb of the entity name and
// renders the entity it returns; what names the action in an error.
func runSponsorVerb(name, verb string, body map[string]any, what string) error {
	if err := validateEntityName(name); err != nil {
		return err
	}
	c, err := helpers.Client()
	if err != nil {
		return err
	}
	if helpers.ResolveDryRun() {
		return helpers.DryRun(c, "POST", "sys/identity/sponsor/{entity}/"+verb, body)
	}
	resource, err := c.Operator().Post("sys/identity/sponsor/"+name+"/"+verb, body)
	if err != nil {
		return fmt.Errorf("error %s entity %q: %w", what, name, err)
	}
	return renderEntityWrite(resource, name, "updated")
}
