package skills

import (
	"fmt"
	"sort"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	readRaw bool

	ReadCmd = &cobra.Command{
		Use:           "read NAME",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Read one skill's full record",
		Long: `
Usage: warden skill read NAME [options]

  Read a single skill by name. The response includes the full markdown
  body so agents can act on the recipe directly. Use --raw to emit
  just the markdown (no JSON wrapper) — convenient for piping into a
  pager or rendering with another tool.

  Output honors the global --output flag (table, json, ndjson, text).
  --raw overrides --output and always emits plain markdown to stdout.

  Examples:

    Read the discovery skill as JSON for an agent:

      $ warden skill read discovery -o json

    Get the raw markdown to pipe into a renderer:

      $ warden skill read aws --raw | glow -
`,
		Args: cobra.ExactArgs(1),
		RunE: runRead,
	}
)

func init() {
	ReadCmd.Flags().BoolVar(&readRaw, "raw", false,
		"Emit only the markdown body, bypassing --output and the JSON envelope")
}

func runRead(cmd *cobra.Command, args []string) error {
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	name := args[0]
	resource, err := c.Operator().Read("sys/skills/" + name)
	if err != nil {
		return fmt.Errorf("failed to read skill %q: %w", name, err)
	}
	if resource == nil || resource.Data == nil {
		return fmt.Errorf("skill %q not found", name)
	}

	if readRaw {
		body, _ := resource.Data["body"].(string)
		fmt.Print(body)
		return nil
	}

	return helpers.RenderMap(resource.Data, func() {
		printSkillRecordTable(resource.Data)
	})
}

func printSkillRecordTable(data map[string]any) {
	keys := make([]string, 0, len(data))
	for k := range data {
		if k == "body" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	rows := make([][]any, 0, len(keys)+1)
	for _, k := range keys {
		rows = append(rows, []any{k, fmt.Sprintf("%v", data[k])})
	}
	helpers.PrintTable([]string{"Key", "Value"}, rows)

	// Body goes below the metadata table — it's typically several lines
	// of markdown and would wreck a key/value table layout.
	if body, _ := data["body"].(string); body != "" {
		fmt.Println()
		fmt.Println("--- body ---")
		fmt.Print(body)
		if body[len(body)-1] != '\n' {
			fmt.Println()
		}
	}
}
