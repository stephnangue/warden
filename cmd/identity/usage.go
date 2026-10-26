package identity

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
)

var UsageCmd = &cobra.Command{
	Use:           "usage",
	SilenceUsage:  true,
	SilenceErrors: true,
	Short:         "Show how much of its caps the namespace's identity objects use",
	Long: `
Usage: warden identity usage

  Count the current namespace's identity objects by kind, against their
  caps. Groups: every group, and the virtual groups with the selectors of
  their rules ("mount" included). Identities: the entities, and the native
  identities they claim. Needs read on sys/identity/usage; no sudo.

  Output honors the global -output flag:
    table    one section per kind (default for TTY), each count shown
             against its cap as used/max:

               GROUPS
                 TYPE      COUNT          SELECTORS
                 virtual   <count>/<max>  <selectors>/<max>
                 total     <count>

               IDENTITIES
                 entities  <count>/<max>
                 aliases   <count>

    json     the server's data as is:
             {"groups": {"total", "virtual": {"count", "max",
             "selectors", "max_selectors"}},
             "identities": {"entities", "max_entities", "aliases"}}

  Examples:

      $ warden identity usage
      $ warden identity usage -o json | jq .groups.virtual
      $ warden identity usage -o json | jq .identities
`,
	Args: cobra.NoArgs,
	RunE: runUsage,
}

func runUsage(cmd *cobra.Command, args []string) error {
	c, err := helpers.Client()
	if err != nil {
		return err
	}
	u, err := c.Sys().ReadIdentityUsage()
	if err != nil {
		return fmt.Errorf("failed to read identity usage: %w", err)
	}
	data, err := usageData(u)
	if err != nil {
		return err
	}
	return helpers.RenderMap(data, func() {
		printUsage(os.Stdout, u)
	})
}

// usageData renders u as the server's response data, for the structured
// output formats.
func usageData(u *api.IdentityUsage) (map[string]any, error) {
	raw, err := json.Marshal(u)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// printUsage writes the usage table: one section per kind of object.
func printUsage(w io.Writer, u *api.IdentityUsage) {
	g := u.Groups
	fmt.Fprintln(w, "GROUPS")
	tw := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)
	fmt.Fprintln(tw, "  TYPE\tCOUNT\tSELECTORS")
	fmt.Fprintf(tw, "  virtual\t%d/%d\t%d/%d\n", g.Virtual.Count, g.Virtual.Max, g.Virtual.Selectors, g.Virtual.MaxSelectors)
	fmt.Fprintf(tw, "  total\t%d\n", g.Total)
	_ = tw.Flush()

	id := u.Identities
	fmt.Fprintln(w)
	fmt.Fprintln(w, "IDENTITIES")
	tw = tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)
	fmt.Fprintf(tw, "  entities\t%d/%d\n", id.Entities, id.MaxEntities)
	fmt.Fprintf(tw, "  aliases\t%d\n", id.Aliases)
	_ = tw.Flush()
}
