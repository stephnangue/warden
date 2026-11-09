package identity

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	memberUntil string
	memberFor   time.Duration

	GroupMemberCmd = &cobra.Command{
		Use:   "member",
		Short: "Add or remove a member of a static group",
		Long: `
Usage: warden identity group member <subcommand> [options]

  Change one member of a static group, keeping the others. Each command
  reads the group, changes its member list, and writes it back only if
  nobody changed the group in between (expected_hash), trying once more
  if someone did. Requires a token with sudo on sys/identity/group.

      $ warden identity group member add local-ops invoice-agent
      $ warden identity group member add local-ops release-bot -for 72h
      $ warden identity group member remove local-ops release-bot
`,
	}

	GroupMemberAddCmd = &cobra.Command{
		Use:           "add <group> <entity>",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Add an entity to a static group, or change its until (sudo)",
		Long: `
Usage: warden identity group member add <group> <entity> [-until <RFC 3339> | -for <duration>]

  Add an entity of this namespace to a static group. Its membership counts
  only while the entity is governed and active. -until (an RFC 3339
  instant) or -for (a duration from now) ends it: it grants through that
  instant and nothing after. Adding a member already listed replaces its
  until; adding it again with neither flag makes it permanent.

      $ warden identity group member add local-ops invoice-agent
      $ warden identity group member add local-ops release-bot -for 72h
      $ warden identity group member add local-ops release-bot -until 2026-12-31T23:59:59Z
`,
		Args: cobra.ExactArgs(2),
		RunE: runGroupMemberAdd,
	}

	GroupMemberRemoveCmd = &cobra.Command{
		Use:           "remove <group> <entity>",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Remove an entity from a static group (sudo)",
		Long: `
Usage: warden identity group member remove <group> <entity>

  Remove an entity from a static group. It loses the roles the group
  grants on its next request.

      $ warden identity group member remove local-ops release-bot
`,
		Args: cobra.ExactArgs(2),
		RunE: runGroupMemberRemove,
	}

	GroupPruneCmd = &cobra.Command{
		Use:           "prune <group>",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Drop a static group's expired members (sudo)",
		Long: `
Usage: warden identity group prune <group>

  Drop the members of a static group whose until has passed. Any write of
  the group drops them too; an expired member already grants nothing, and
  is listed as expired until a write drops it. The warning names the
  members dropped.

      $ warden identity group prune local-ops
`,
		Args: cobra.ExactArgs(1),
		RunE: runGroupPrune,
	}
)

func init() {
	GroupMemberAddCmd.Flags().StringVar(&memberUntil, "until", "",
		"RFC 3339 instant after which the membership ends, e.g. 2026-12-31T23:59:59Z")
	GroupMemberAddCmd.Flags().DurationVar(&memberFor, "for", 0, "How long the membership lasts from now, e.g. 72h")
	GroupMemberCmd.AddCommand(GroupMemberAddCmd)
	GroupMemberCmd.AddCommand(GroupMemberRemoveCmd)
}

func runGroupMemberAdd(cmd *cobra.Command, args []string) error {
	group, entity := args[0], args[1]
	if err := validateGroupName(group); err != nil {
		return err
	}
	if memberUntil != "" && memberFor != 0 {
		return fmt.Errorf("-until and -for are mutually exclusive: %w", helpers.ErrUsage)
	}
	until := memberUntil
	if until != "" {
		if _, err := time.Parse(time.RFC3339Nano, until); err != nil {
			return fmt.Errorf("-until must be an RFC 3339 instant, e.g. 2026-12-31T23:59:59Z: %w", helpers.ErrUsage)
		}
	}
	if memberFor < 0 {
		return fmt.Errorf("-for must be positive: %w", helpers.ErrUsage)
	}
	if memberFor > 0 {
		until = time.Now().Add(memberFor).UTC().Format(time.RFC3339)
	}
	if t, err := time.Parse(time.RFC3339Nano, until); err == nil && time.Now().After(t) {
		return fmt.Errorf("-until %s is already past: the membership would end before it starts: %w", until, helpers.ErrUsage)
	}
	c, err := helpers.Client()
	if err != nil {
		return err
	}
	if helpers.ResolveDryRun() {
		var member any = entity
		if until != "" {
			member = map[string]any{"name": entity, "until": until}
		}
		return helpers.DryRun(c, "PUT", "sys/identity/group/{name}", map[string]any{"type": "static", "members": []any{member}})
	}
	g, err := editMembers(c, group, func(members []api.GroupMemberInput) []api.GroupMemberInput {
		members = slices.DeleteFunc(members, func(m api.GroupMemberInput) bool { return m.Name == entity })
		return append(members, api.GroupMemberInput{Name: entity, Until: until})
	})
	if err != nil {
		return fmt.Errorf("error adding %q to group %q: %w", entity, group, err)
	}
	return renderGroup(g, group, "updated")
}

func runGroupMemberRemove(cmd *cobra.Command, args []string) error {
	group, entity := args[0], args[1]
	if err := validateGroupName(group); err != nil {
		return err
	}
	c, err := helpers.Client()
	if err != nil {
		return err
	}
	if helpers.ResolveDryRun() {
		return helpers.DryRun(c, "PUT", "sys/identity/group/{name}", map[string]any{"type": "static", "members": []any{}})
	}
	found := false
	g, err := editMembers(c, group, func(members []api.GroupMemberInput) []api.GroupMemberInput {
		n := len(members)
		members = slices.DeleteFunc(members, func(m api.GroupMemberInput) bool { return m.Name == entity })
		found = len(members) < n
		return members
	})
	if err != nil {
		return fmt.Errorf("error removing %q from group %q: %w", entity, group, err)
	}
	if !found {
		return fmt.Errorf("entity %q is not a member of group %q: %w", entity, group, helpers.ErrNotFound)
	}
	return renderGroup(g, group, "updated")
}

func runGroupPrune(cmd *cobra.Command, args []string) error {
	group := args[0]
	if err := validateGroupName(group); err != nil {
		return err
	}
	c, err := helpers.Client()
	if err != nil {
		return err
	}
	if helpers.ResolveDryRun() {
		return helpers.DryRun(c, "PUT", "sys/identity/group/{name}", map[string]any{"type": "static"})
	}
	// A write with no change: the server drops the expired members.
	g, err := c.Sys().UpdateGroup(group, &api.GroupInput{Type: "static"})
	if err != nil {
		return fmt.Errorf("error pruning group %q: %w", group, err)
	}
	return renderGroup(g, group, "updated")
}

// editMembers reads the static group name, applies edit to its member list
// and writes the result back, conditional on the hash it read. A write that
// loses to a concurrent one is read and edited again once; the edit must be
// safe to run twice. The type is sent as "static", so a group of another
// type is refused.
func editMembers(c *api.Client, name string, edit func([]api.GroupMemberInput) []api.GroupMemberInput) (*api.Group, error) {
	for attempt := 1; ; attempt++ {
		g, err := c.Sys().ReadGroup(name, "static")
		if err != nil {
			return nil, err
		}
		// The members read are written back by ID: an entity deleted and
		// created again under the same name in between is not taken for the
		// one read. Name is kept for edit to match on.
		members := make([]api.GroupMemberInput, 0, len(g.Members))
		for _, m := range g.Members {
			members = append(members, api.GroupMemberInput{ID: m.ID, Name: m.Name, Until: m.Until})
		}
		out, err := c.Sys().UpdateGroup(name, &api.GroupInput{Type: "static", Members: edit(members), ExpectedHash: g.Hash})
		var re *api.ResponseError
		if attempt < 2 && errors.As(err, &re) && re.StatusCode == http.StatusConflict {
			continue
		}
		return out, err
	}
}

// renderGroup prints a group a write returned, with its warnings on stderr.
func renderGroup(g *api.Group, name, marker string) error {
	helpers.PrintWarnings(g.Warnings)
	raw, err := json.Marshal(g)
	if err != nil {
		return err
	}
	out := map[string]any{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return err
	}
	out["name"], out[marker] = name, true
	return helpers.RenderMap(out, func() {
		printGroupTable(out)
	})
}
