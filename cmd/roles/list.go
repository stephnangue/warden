package roles

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	listAll            bool
	providerPathFilter string

	ListCmd = &cobra.Command{
		Use:           "list",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Discover roles the presented identity can assume, or list every role (-all)",
		Long: `
Usage: warden role list [options]

  Lists every role of the current namespace that a group grants the
  caller's identity, presented as the JWT bearer token or the TLS client
  certificate the request was made with. Each role is checked at the auth
  mount a request for it would authenticate through: the auto_auth_path of
  its provider, or the namespace's auto_auth_path for a role without one.
  Warden never needs the role names to be distributed out-of-band.

  With -all, lists instead every role defined in the current namespace
  (the operator inventory), each with the groups that grant it
  ("granted_by", from one listing of sys/identity/group). It requires a
  token with sudo on sys/roles (and on sys/identity/group for granted_by),
  and -provider-path narrows it to the roles used with one provider.

  Output honors the global -output flag:
    table    one row per role (default for TTY)
    json     [{"name", "description", "provider_path", "skill"}, ...]
             (provider_path and skill only when the role sets them)
             with -all: [{"name", "description", "granted_by",
             "policies", "cred_spec_name", "provider_path", "skill",
             "metadata"}, ...]
    ndjson   one role per line, agent-friendly for piping into jq
    text     key=value lines per role

  Composes with -fields, e.g. -fields name,provider_path to project to just
  those two fields per record.

  Auth mounts that cannot decide are reported as warnings on stderr; the
  command still exits 0 so one failing mount cannot mask the rest of the
  namespace's roles.

  Examples:

    Show every role the caller can assume:

      $ warden role list

    JSON for agents:

      $ warden role list -o json

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

	c, err := helpers.Client()
	if err != nil {
		return err
	}

	resource, err := c.Operator().ReadWithData("sys/introspect/roles", nil)
	if err != nil {
		return fmt.Errorf("failed to introspect roles: %w", err)
	}

	var rawRoles []any
	var data map[string]any
	if resource != nil && resource.Data != nil {
		data = resource.Data
		rawRoles, _ = data["roles"].([]any)
	}

	items := projectRoles(rawRoles)

	// Failing mounts are reported on stderr without changing the exit code:
	// one mount erroring must not hide the rest of the namespace's roles.
	// Agents reading stdout JSON see a clean role list.
	helpers.PrintWarnings(helpers.WarningsFromData(data))

	return helpers.RenderList(items, func() {
		printRolesTable(items)
	})
}

// runListAll lists every role of the namespace through LIST sys/roles.
func runListAll() error {
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
	grants, err := grantingGroups(c, "")
	if err != nil {
		helpers.PrintWarnings([]string{fmt.Sprintf("cannot list groups to fill granted_by: %v", err)})
	}

	items := projectInventory(roles, grants)
	return helpers.RenderList(items, func() {
		printInventoryTable(items)
	})
}

// projectInventory shapes the namespace's roles for output. grants maps a role
// to the groups granting it; when it is nil (the groups could not be listed)
// granted_by is left out rather than shown empty.
func projectInventory(roles []*api.Role, grants map[string][]string) []map[string]any {
	items := make([]map[string]any, 0, len(roles))
	for _, r := range roles {
		policies := r.Policies
		if policies == nil {
			policies = []string{}
		}
		metadata := make(map[string]any, len(r.Metadata))
		for k, v := range r.Metadata {
			metadata[k] = v
		}
		item := map[string]any{
			"name":           r.Name,
			"description":    r.Description,
			"policies":       policies,
			"cred_spec_name": r.CredSpecName,
			"provider_path":  r.ProviderPath,
			"skill":          r.Skill,
			"metadata":       metadata,
		}
		if grants != nil {
			item["granted_by"] = stringsToAny(grants[r.Name])
		}
		items = append(items, item)
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
			cell(it["granted_by"]),
			cell(it["policies"]),
			cell(it["cred_spec_name"]),
			cell(it["provider_path"]),
			cell(it["skill"]),
			cell(it["metadata"]),
		}
	}
	helpers.PrintTable([]string{"Name", "Description", "Granted By", "Policies", "Cred Spec", "Provider Path", "Skill", "Metadata"}, rows)
}

// projectRoles shapes the discovered roles for output. The discovery fields
// (skill, provider_path) appear only on roles that set them.
func projectRoles(rawRoles []any) []map[string]any {
	items := make([]map[string]any, 0, len(rawRoles))
	for _, r := range rawRoles {
		rm, ok := r.(map[string]any)
		if !ok {
			continue
		}
		item := map[string]any{
			"name":        rm["name"],
			"description": rm["description"],
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

// rolesTable returns the header and rows of the discovered roles' table.
func rolesTable(items []map[string]any) ([]string, [][]any) {
	rows := make([][]any, len(items))
	for i, it := range items {
		rows[i] = []any{
			cell(it["name"]),
			cell(it["description"]),
			cell(it["provider_path"]),
			cell(it["skill"]),
		}
	}
	return []string{"Name", "Description", "Provider Path", "Skill"}, rows
}

func printRolesTable(items []map[string]any) {
	if len(items) == 0 {
		fmt.Println("No roles available for the presented identity.")
		return
	}
	helpers.PrintTable(rolesTable(items))
}
