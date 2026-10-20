package identity

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	listRole string

	GroupListCmd = &cobra.Command{
		Use:           "list",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "List the groups of the current namespace (sudo)",
		Long: `
Usage: warden identity group list [options]

  List every group of the current namespace, or with -role only the
  groups that grant one role. Requires a token with sudo on
  sys/identity/group.

  Output honors the global -output flag:
    table    one row per group (default for TTY)
    json     [{"name", "type", "description", "roles", "selectors",
             "max_age", "metadata", "hash"}, ...]
    ndjson   one group per line

  Examples:

      $ warden identity group list
      $ warden identity group list -role deploy
      $ warden identity group list -o ndjson | jq -r .name
`,
		Args: cobra.NoArgs,
		RunE: runGroupList,
	}
)

func init() {
	GroupListCmd.Flags().StringVar(&listRole, "role", "", "List only the groups that grant this role")
}

func runGroupList(cmd *cobra.Command, args []string) error {
	if listRole != "" {
		if err := helpers.ValidateIdentifier("role name", listRole); err != nil {
			return err
		}
	}
	c, err := helpers.Client()
	if err != nil {
		return err
	}
	groups, err := c.Sys().ListGroups(listRole)
	if err != nil {
		return fmt.Errorf("failed to list groups: %w", err)
	}
	items := projectGroups(groups)
	return helpers.RenderList(items, func() {
		printGroupsTable(items)
	})
}

func projectGroups(groups []*api.Group) []map[string]any {
	items := make([]map[string]any, 0, len(groups))
	for _, g := range groups {
		roles := g.Roles
		if roles == nil {
			roles = []string{}
		}
		selectors := make([]any, 0, len(g.Selectors))
		for _, s := range g.Selectors {
			m := make(map[string]any, len(s))
			for k, vs := range s {
				m[k] = stringsToAny(vs)
			}
			selectors = append(selectors, m)
		}
		metadata := make(map[string]any, len(g.Metadata))
		for k, v := range g.Metadata {
			metadata[k] = v
		}
		items = append(items, map[string]any{
			"name":        g.Name,
			"type":        g.Type,
			"description": g.Description,
			"roles":       roles,
			"selectors":   selectors,
			"max_age":     g.MaxAge,
			"metadata":    metadata,
			"hash":        g.Hash,
		})
	}
	return items
}

func printGroupsTable(items []map[string]any) {
	if len(items) == 0 {
		fmt.Println("No groups defined in this namespace.")
		return
	}
	rows := make([][]any, len(items))
	for i, it := range items {
		sel, _ := it["selectors"].([]any)
		rows[i] = []any{
			cell(it["name"]),
			cell(it["type"]),
			cell(it["roles"]),
			fmt.Sprint(len(sel)),
			cell(it["max_age"]),
			cell(it["description"]),
		}
	}
	helpers.PrintTable([]string{"Name", "Type", "Roles", "Selectors", "Max Age", "Description"}, rows)
}
