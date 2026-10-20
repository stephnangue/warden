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
  groups that grant one role, and how much of the namespace's caps its
  groups use: every group, and every selector of every rule ("mount"
  included). The usage always covers the whole namespace, whatever the
  filter. Requires a token with sudo on sys/identity/group.

  Output honors the global -output flag:
    table    one row per group, then a usage footer (default for TTY):
             groups 42/8000 · selectors 310/16000
    json     {"groups": [{"name", "type", "description", "roles",
             "rules", "rule_count", "selector_count", "max_age",
             "metadata", "hash"}, ...],
             "usage": {"groups", "max_groups", "selectors",
             "max_selectors"}}
    ndjson   one group per line, without the usage

  Examples:

      $ warden identity group list
      $ warden identity group list -role deploy
      $ warden identity group list -o json | jq .usage
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
	list, err := c.Sys().ListGroups(listRole)
	if err != nil {
		return fmt.Errorf("failed to list groups: %w", err)
	}
	items := projectGroups(list.Groups)

	// One group per line for ndjson, as agents pipe it; the usage, which
	// belongs to no group, rides only in the json and table forms.
	if helpers.ResolveFormat() == helpers.FormatNDJSON {
		return helpers.RenderList(items, nil)
	}
	return helpers.RenderMap(map[string]any{
		"groups": items,
		"usage": map[string]any{
			"groups":        list.Usage.Groups,
			"max_groups":    list.Usage.MaxGroups,
			"selectors":     list.Usage.Selectors,
			"max_selectors": list.Usage.MaxSelectors,
		},
	}, func() {
		printGroupsTable(items)
		fmt.Println(usageFooter(list.Usage))
	})
}

// usageFooter renders the namespace's usage of its caps on one line.
func usageFooter(u api.GroupUsage) string {
	return fmt.Sprintf("groups %d/%d · selectors %d/%d", u.Groups, u.MaxGroups, u.Selectors, u.MaxSelectors)
}

func projectGroups(groups []*api.Group) []map[string]any {
	items := make([]map[string]any, 0, len(groups))
	for _, g := range groups {
		roles := g.Roles
		if roles == nil {
			roles = []string{}
		}
		rules := make([]any, 0, len(g.Rules))
		for _, r := range g.Rules {
			m := make(map[string]any, len(r))
			for k, vs := range r {
				m[k] = stringsToAny(vs)
			}
			rules = append(rules, m)
		}
		metadata := make(map[string]any, len(g.Metadata))
		for k, v := range g.Metadata {
			metadata[k] = v
		}
		items = append(items, map[string]any{
			"name":           g.Name,
			"type":           g.Type,
			"description":    g.Description,
			"roles":          roles,
			"rules":          rules,
			"rule_count":     g.RuleCount,
			"selector_count": g.SelectorCount,
			"max_age":        g.MaxAge,
			"metadata":       metadata,
			"hash":           g.Hash,
		})
	}
	return items
}

func printGroupsTable(items []map[string]any) {
	if len(items) == 0 {
		fmt.Println("No groups to list.")
		return
	}
	rows := make([][]any, len(items))
	for i, it := range items {
		rows[i] = []any{
			cell(it["name"]),
			cell(it["type"]),
			cell(it["roles"]),
			cell(it["rule_count"]),
			cell(it["selector_count"]),
			cell(it["max_age"]),
			cell(it["description"]),
		}
	}
	helpers.PrintTable([]string{"Name", "Type", "Roles", "Rules", "Selectors", "Max Age", "Description"}, rows)
}
