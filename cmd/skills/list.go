package skills

import (
	"fmt"
	"sort"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	listCategoryFilter string
	listOriginFilter   string
	listProviderFilter string

	ListCmd = &cobra.Command{
		Use:           "list",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "List every skill in the global registry",
		Long: `
Usage: warden skill list [options]

  Returns the agent skill catalog. The list endpoint returns short-form
  records (no markdown body) to keep the response cheap; agents that need
  full content fetch each name via 'warden skill read NAME'.

  Output honors the global -output flag:
    table    one row per skill (default for TTY)
    json     [{"name", "description", "category", "origin", ...}, ...]
    ndjson   one skill per line, agent-friendly for piping into jq
    text     key=value lines per record

  Composes with -fields, e.g. -fields name,category to project per record.

  Examples:

    All skills:

      $ warden skill list

    Only provider-guide skills, JSON for agents:

      $ warden skill list -category=provider-guide -o json

    Only operator-created skills:

      $ warden skill list -origin=user
`,
		Args: cobra.NoArgs,
		RunE: runList,
	}
)

func init() {
	ListCmd.Flags().StringVar(&listCategoryFilter, "category", "",
		"Filter by category (agent-flow, shared, provider-guide, troubleshooting, custom)")
	ListCmd.Flags().StringVar(&listOriginFilter, "origin", "",
		"Filter by origin (seed for binary-shipped, user for operator-created)")
	ListCmd.Flags().StringVar(&listProviderFilter, "provider", "",
		"Filter by provider type (only applies to provider-guide category)")
}

func runList(cmd *cobra.Command, args []string) error {
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	resource, err := c.Operator().ReadWithData("sys/skills", map[string][]string{
		"warden-list": {"true"},
	})
	if err != nil {
		return fmt.Errorf("failed to list skills: %w", err)
	}

	var raw []any
	if resource != nil && resource.Data != nil {
		raw, _ = resource.Data["skills"].([]any)
	}

	items := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		rm, ok := r.(map[string]any)
		if !ok {
			continue
		}
		if listCategoryFilter != "" {
			if cat, _ := rm["category"].(string); cat != listCategoryFilter {
				continue
			}
		}
		if listOriginFilter != "" {
			if origin, _ := rm["origin"].(string); origin != listOriginFilter {
				continue
			}
		}
		if listProviderFilter != "" {
			if prov, _ := rm["provider"].(string); prov != listProviderFilter {
				continue
			}
		}
		items = append(items, rm)
	}

	// Stable, alphabetical order for deterministic agent output.
	sort.Slice(items, func(i, j int) bool {
		ni, _ := items[i]["name"].(string)
		nj, _ := items[j]["name"].(string)
		return ni < nj
	})

	return helpers.RenderList(items, func() {
		printSkillsTable(items)
	})
}

func printSkillsTable(items []map[string]any) {
	if len(items) == 0 {
		fmt.Println("No skills match the filters.")
		return
	}
	rows := make([][]any, len(items))
	for i, it := range items {
		rows[i] = []any{
			fmt.Sprintf("%v", it["name"]),
			fmt.Sprintf("%v", it["category"]),
			fmt.Sprintf("%v", it["origin"]),
			fmt.Sprintf("%v", it["description"]),
		}
	}
	helpers.PrintTable([]string{"Name", "Category", "Origin", "Description"}, rows)
}
