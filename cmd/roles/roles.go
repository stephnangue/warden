// Package roles implements `warden roles`, the agent-facing role-introspection
// command. It hits the server endpoint at /v1/sys/introspect/roles which fans
// out to every auth mount of the caller's identity type (JWT or cert) in the
// current namespace and returns the union of roles each mount reports the
// identity can assume.
package roles

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	authPathFilter string

	RolesCmd = &cobra.Command{
		Use:           "roles",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Discover roles the presented identity can assume",
		Long: `
Usage: warden roles

  Lists every Warden role the caller's identity vehicle can assume, across
  every auth mount of the matching credential type in the current namespace.
  The endpoint introspects from the JWT bearer token or the TLS client
  certificate the request was made with — Warden never needs the role names
  to be distributed out-of-band.

  Output honors the global --output flag:
    table    one row per role (default for TTY)
    json     [{"name", "description", "auth_path"}, ...]
    ndjson   one role per line, agent-friendly for piping into jq
    text     key=value lines per role

  Composes with --fields, e.g. --fields name,auth_path to project to just
  those two fields per record.

  Mounts that fail introspection are reported as warnings on stderr; the
  command still exits 0 so a partial-failure mount cannot mask the rest
  of the namespace's roles.

  Examples:

    Show every role the caller can assume:

      $ warden roles

    JSON for agents:

      $ warden roles -o json

    Filter to a specific auth mount:

      $ warden roles --auth-path auth/jwt/

    Pipe just the names into jq:

      $ warden roles -o ndjson | jq -r .name
`,
		Args: cobra.NoArgs,
		RunE: runRoles,
	}
)

func init() {
	RolesCmd.Flags().StringVar(&authPathFilter, "auth-path", "",
		"Restrict results to roles on a single auth mount (e.g. \"auth/jwt/\")")
}

func runRoles(cmd *cobra.Command, args []string) error {
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
		items = append(items, map[string]any{
			"name":        rm["name"],
			"description": rm["description"],
			"auth_path":   ap,
		})
	}

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

func printRolesTable(items []map[string]any) {
	if len(items) == 0 {
		fmt.Println("No roles available for the presented identity.")
		return
	}
	rows := make([][]any, len(items))
	for i, it := range items {
		rows[i] = []any{
			fmt.Sprintf("%v", it["name"]),
			fmt.Sprintf("%v", it["description"]),
			fmt.Sprintf("%v", it["auth_path"]),
		}
	}
	helpers.PrintTable([]string{"Name", "Description", "Auth Path"}, rows)
}
