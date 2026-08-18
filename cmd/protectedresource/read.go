package protectedresource

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var ReadCmd = &cobra.Command{
	Use:           "read",
	SilenceUsage:  true,
	SilenceErrors: true,
	Short:         "Read the protected resource metadata configuration",
	Long: `
Usage: warden protected-resource read

  Show the deployment-wide protected resource metadata configuration. Root
  namespace only.

      $ warden protected-resource read

  "enabled" reflects whether resource_url is set — no base URL means no document
  can name a resource, so nothing is served.
`,
	Args: cobra.NoArgs,
	RunE: runRead,
}

func runRead(cmd *cobra.Command, args []string) error {
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	resource, err := c.Operator().Read(protectedResourceConfigPath)
	if err != nil {
		return fmt.Errorf("error reading protected resource configuration: %w", err)
	}
	if resource == nil || resource.Data == nil {
		fmt.Fprintln(os.Stderr, "No protected resource configuration found.")
		return nil
	}

	return helpers.RenderMap(resource.Data, func() {
		printConfigTable(resource.Data)
	})
}

// fieldOrder is the stable display order, most-load-bearing first.
var fieldOrder = []string{
	"enabled",
	"resource_url",
	"authorization_servers",
	"resource_documentation",
	"cache_ttl",
}

func printConfigTable(data map[string]any) {
	var rows [][]any
	for _, k := range fieldOrder {
		v, ok := data[k]
		if !ok {
			continue
		}
		rows = append(rows, []any{k, cellString(k, v)})
	}
	helpers.PrintTable([]string{"Field", "Value"}, rows)
}

// cellString renders a value for the table. cache_ttl arrives as integer
// seconds from the server and is humanised here.
func cellString(key string, v any) string {
	switch key {
	case "cache_ttl":
		if secs, ok := toSeconds(v); ok {
			return (time.Duration(secs) * time.Second).String()
		}
	case "authorization_servers":
		if list, ok := v.([]any); ok {
			if len(list) == 0 {
				return "(derived per mount)"
			}
			parts := make([]string, 0, len(list))
			for _, item := range list {
				parts = append(parts, fmt.Sprintf("%v", item))
			}
			return strings.Join(parts, ", ")
		}
	}
	if v == nil || v == "" {
		return "-"
	}
	return fmt.Sprintf("%v", v)
}

// toSeconds extracts an integer seconds value from a JSON-decoded number.
func toSeconds(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case int64:
		return n, true
	case int:
		return int64(n), true
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return i, true
		}
	}
	return 0, false
}
