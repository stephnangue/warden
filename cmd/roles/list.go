package roles

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	authPathFilter     string
	listAll            bool
	providerPathFilter string

	ListCmd = &cobra.Command{
		Use:           "list",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Discover roles the presented identity can assume, or list every role (-all)",
		Long: `
Usage: warden role list [options]

  Lists every Warden role the caller's identity vehicle can assume, across
  every auth mount of the matching credential type in the current namespace.
  The endpoint introspects from the JWT bearer token or the TLS client
  certificate the request was made with — Warden never needs the role names
  to be distributed out-of-band.

  With -all, lists instead every role defined in the current namespace
  (the operator inventory). It requires a token with sudo on sys/roles,
  and -provider-path narrows it to the roles used with one provider.

  Output honors the global -output flag:
    table    one row per role (default for TTY)
    json     [{"name", "description", "auth_path"}, ...]
             with -all: [{"name", "description", "policies",
             "cred_spec_name", "provider_path", "skill"}, ...]
    ndjson   one role per line, agent-friendly for piping into jq
    text     key=value lines per role

  Composes with -fields, e.g. -fields name,auth_path to project to just
  those two fields per record.

  Mounts that fail introspection are reported as warnings on stderr; the
  command still exits 0 so a partial-failure mount cannot mask the rest
  of the namespace's roles.

  Examples:

    Show every role the caller can assume:

      $ warden role list

    JSON for agents:

      $ warden role list -o json

    Filter to a specific auth mount:

      $ warden role list -auth-path auth/jwt/

    Pipe just the names into jq:

      $ warden role list -o ndjson | jq -r .name

    Every role of the namespace (sudo):

      $ warden role list -all

    Every role used with the aws/ provider (sudo):

      $ warden role list -all -provider-path aws/
`,
		Args: cobra.NoArgs,
		RunE: runList,
	}
)

func init() {
	ListCmd.Flags().StringVar(&authPathFilter, "auth-path", "",
		"Restrict results to roles on a single auth mount (e.g. \"auth/jwt/\")")
	ListCmd.Flags().BoolVar(&listAll, "all", false,
		"List every role defined in the namespace instead of the ones the presented identity can assume (sudo)")
	ListCmd.Flags().StringVar(&providerPathFilter, "provider-path", "",
		"With -all, list only the roles used with this provider mount path (e.g. \"aws/\")")
}

func runList(cmd *cobra.Command, args []string) error {
	if listAll {
		return runListAll()
	}
	if providerPathFilter != "" {
		return fmt.Errorf("-provider-path requires -all: %w", helpers.ErrUsage)
	}
	if authPathFilter != "" {
		if err := helpers.ValidatePath(authPathFilter); err != nil {
			return err
		}
	}

	c, err := helpers.Client()
	if err != nil {
		return err
	}

	resource, err := c.Operator().ReadWithData("sys/introspect/roles", nil)
	if err != nil {
		return fmt.Errorf("failed to introspect roles: %w", err)
	}

	var rawRoles []any
	var rawWarnings []any
	if resource != nil && resource.Data != nil {
		rawRoles, _ = resource.Data["roles"].([]any)
		rawWarnings, _ = resource.Data["warnings"].([]any)
	}

	items := projectRoles(rawRoles, authPathFilter)

	// Per-mount failures are surfaced on stderr without changing the exit
	// code: the central design is that a single mount erroring shouldn't
	// hide the rest of the namespace's roles. Agents reading stdout JSON
	// see a clean role list; operators tailing stderr see why a mount
	// dropped out.
	for _, w := range rawWarnings {
		if s, ok := w.(string); ok && s != "" {
			fmt.Fprintln(os.Stderr, "warning:", s)
		}
	}

	return helpers.RenderList(items, func() {
		printRolesTable(items)
	})
}

// runListAll lists every role of the namespace through LIST sys/roles.
func runListAll() error {
	if authPathFilter != "" {
		return fmt.Errorf("-auth-path cannot be combined with -all: %w", helpers.ErrUsage)
	}
	if providerPathFilter != "" {
		if err := helpers.ValidatePath(providerPathFilter); err != nil {
			return err
		}
	}

	c, err := helpers.Client()
	if err != nil {
		return err
	}
	roles, err := c.Sys().ListRoles(providerPathFilter)
	if err != nil {
		return fmt.Errorf("failed to list roles: %w", err)
	}

	items := projectInventory(roles)
	return helpers.RenderList(items, func() {
		printInventoryTable(items)
	})
}

// projectInventory shapes the namespace's roles for output.
func projectInventory(roles []*api.Role) []map[string]any {
	items := make([]map[string]any, 0, len(roles))
	for _, r := range roles {
		policies := r.Policies
		if policies == nil {
			policies = []string{}
		}
		items = append(items, map[string]any{
			"name":           r.Name,
			"description":    r.Description,
			"policies":       policies,
			"cred_spec_name": r.CredSpecName,
			"provider_path":  r.ProviderPath,
			"skill":          r.Skill,
		})
	}
	return items
}

func printInventoryTable(items []map[string]any) {
	if len(items) == 0 {
		fmt.Println("No roles defined in this namespace.")
		return
	}
	rows := make([][]any, len(items))
	for i, it := range items {
		rows[i] = []any{
			cell(it["name"]),
			cell(it["description"]),
			cell(it["policies"]),
			cell(it["cred_spec_name"]),
			cell(it["provider_path"]),
			cell(it["skill"]),
		}
	}
	helpers.PrintTable([]string{"Name", "Description", "Policies", "Cred Spec", "Provider Path", "Skill"}, rows)
}

// projectRoles shapes the aggregator's raw roles for output, keeping only
// those on authPathFilter when it is set. The discovery fields (skill,
// provider_path) appear only on roles that set them.
func projectRoles(rawRoles []any, authPathFilter string) []map[string]any {
	items := make([]map[string]any, 0, len(rawRoles))
	for _, r := range rawRoles {
		rm, ok := r.(map[string]any)
		if !ok {
			continue
		}
		ap, _ := rm["auth_path"].(string)
		if authPathFilter != "" && ap != authPathFilter {
			continue
		}
		item := map[string]any{
			"name":        rm["name"],
			"description": rm["description"],
			"auth_path":   ap,
		}
		for _, k := range []string{"provider_path", "skill"} {
			if v, ok := rm[k]; ok && v != nil && v != "" {
				item[k] = v
			}
		}
		items = append(items, item)
	}
	return items
}

func printRolesTable(items []map[string]any) {
	if len(items) == 0 {
		fmt.Println("No roles available for the presented identity.")
		return
	}
	rows := make([][]any, len(items))
	for i, it := range items {
		rows[i] = []any{
			cell(it["name"]),
			cell(it["description"]),
			cell(it["auth_path"]),
			cell(it["provider_path"]),
			cell(it["skill"]),
		}
	}
	helpers.PrintTable([]string{"Name", "Description", "Auth Path", "Provider Path", "Skill"}, rows)
}
