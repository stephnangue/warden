package identity

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	entityListFilter api.EntityFilter

	EntityListCmd = &cobra.Command{
		Use:           "list",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "List the entities of the current namespace (sudo)",
		Long: `
Usage: warden identity entity list [options]

  List the entities of the current namespace, sorted by name, optionally
  filtered; filters combine. Requires a token with sudo on
  sys/identity/entity.

    -kind, -state, -sponsor, -governed-by   match that field
    -ungoverned   entities without a sponsor or a description
    -orphaned     entities claiming a native identity on an auth mount
                  that no longer exists (disabled with -force)

  Output honors the global -output flag:
    table    one row per entity (default for TTY)
    json     [{"name", "id", "kind", "state", "governed_by",
             "ungoverned_reason", "description", "sponsors", "profile",
             "metadata", "aliases", "hash"}, ...]
    ndjson   one entity per line

  Examples:

      $ warden identity entity list
      $ warden identity entity list -ungoverned
      $ warden identity entity list -state suspended
      $ warden identity entity list -orphaned -o ndjson | jq -r .name
`,
		Args: cobra.NoArgs,
		RunE: runEntityList,
	}
)

func init() {
	fs := EntityListCmd.Flags()
	fs.StringVar(&entityListFilter.Kind, "kind", "", "List only entities of this kind")
	fs.StringVar(&entityListFilter.State, "state", "", "List only entities in this state (active, suspended, retired)")
	fs.StringVar(&entityListFilter.Sponsor, "sponsor", "", "List only entities this sponsor is accountable for")
	fs.StringVar(&entityListFilter.GovernedBy, "governed-by", "", `List only entities governed by this authority ("warden")`)
	fs.BoolVar(&entityListFilter.Ungoverned, "ungoverned", false, "List only ungoverned entities (no sponsor or no description)")
	fs.BoolVar(&entityListFilter.Orphaned, "orphaned", false,
		"List only entities claiming a native identity on an auth mount that no longer exists")
}

func runEntityList(cmd *cobra.Command, args []string) error {
	c, err := helpers.Client()
	if err != nil {
		return err
	}
	entities, err := c.Sys().ListEntities(&entityListFilter)
	if err != nil {
		return fmt.Errorf("failed to list entities: %w", err)
	}
	items := projectEntities(entities)
	return helpers.RenderList(items, func() {
		printEntitiesTable(items)
	})
}

func projectEntities(entities []*api.Entity) []map[string]any {
	items := make([]map[string]any, 0, len(entities))
	for _, e := range entities {
		sponsors := e.Sponsors
		if sponsors == nil {
			sponsors = []string{}
		}
		aliases := make([]map[string]any, 0, len(e.Aliases))
		for _, a := range e.Aliases {
			aliases = append(aliases, map[string]any{
				"mount":          a.Mount,
				"mount_accessor": a.MountAccessor,
				"name":           a.Name,
			})
		}
		items = append(items, map[string]any{
			"name":              e.Name,
			"id":                e.ID,
			"kind":              e.Kind,
			"state":             e.State,
			"governed_by":       e.GovernedBy,
			"ungoverned_reason": e.UngovernedReason,
			"description":       e.Description,
			"sponsors":          sponsors,
			"profile":           stringMapToAny(e.Profile),
			"metadata":          stringMapToAny(e.Metadata),
			"aliases":           aliases,
			"hash":              e.Hash,
		})
	}
	return items
}

func printEntitiesTable(items []map[string]any) {
	if len(items) == 0 {
		fmt.Println("No entities to list.")
		return
	}
	rows := make([][]any, len(items))
	for i, it := range items {
		governed := cell(it["governed_by"])
		if governed == "" {
			governed = "-"
		}
		rows[i] = []any{
			cell(it["name"]),
			cell(it["state"]),
			governed,
			cell(it["sponsors"]),
			len(aliasesOf(it["aliases"])),
			cell(it["description"]),
		}
	}
	helpers.PrintTable([]string{"Name", "State", "Governed By", "Sponsors", "Aliases", "Description"}, rows)
}
