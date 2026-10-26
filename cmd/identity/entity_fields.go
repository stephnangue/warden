package identity

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
)

// entityFlags are the typed flags create and update share. Only the flags the
// user set are sent, so on update an omitted flag keeps the stored value and
// an empty one (e.g. -sponsors="") clears it. -kind and -alias are create
// only, -new-name update only.
type entityFlags struct {
	kind        string
	description string
	sponsors    []string
	state       string
	profile     map[string]string
	metadata    map[string]string
	aliases     []string
	newName     string
}

// entityFlagNames maps each typed flag to the payload key it sets.
var entityFlagNames = []struct{ flag, key string }{
	{"kind", "kind"},
	{"description", "description"},
	{"sponsors", "sponsors"},
	{"state", "state"},
	{"profile", "profile"},
	{"metadata", "metadata"},
	{"alias", "aliases"},
	{"new-name", "new_name"},
}

func (f *entityFlags) bind(cmd *cobra.Command, create bool) {
	fs := cmd.Flags()
	if create {
		fs.StringVar(&f.kind, "kind", "", `Kind of entity: "agent" (the default; the only kind yet). Never changes.`)
		fs.StringArrayVar(&f.aliases, "alias", nil,
			`A native identity the entity claims, as <mount>=<name>, e.g. auth/kubernetes/=system:serviceaccount:billing:agent (repeatable)`)
	} else {
		fs.StringVar(&f.newName, "new-name", "", "Rename the entity; its ID does not change")
	}
	fs.StringVar(&f.description, "description", "", "What the agent does; with a sponsor, it makes the entity governed")
	fs.StringSliceVar(&f.sponsors, "sponsors", nil,
		"The humans accountable for the agent, as UPNs or email addresses (repeat or comma-separated)")
	fs.StringVar(&f.state, "state", "", "active, suspended (reversible) or retired (final; the record becomes read-only)")
	fs.StringToStringVar(&f.profile, "profile", nil, "Descriptive data: purpose=…, runtime=…, publisher=… (repeatable)")
	fs.StringToStringVar(&f.metadata, "metadata", nil, "Free-form label (key=value, repeatable)")
}

// reset restores the zero values. Intended for tests, which reuse the
// package-level commands.
func (f *entityFlags) reset() { *f = entityFlags{} }

func (f *entityFlags) changed(cmd *cobra.Command) map[string]bool {
	out := make(map[string]bool, len(entityFlagNames))
	for _, n := range entityFlagNames {
		if cmd.Flags().Lookup(n.flag) != nil {
			out["-"+n.flag] = cmd.Flags().Changed(n.flag)
		}
	}
	return out
}

// payload builds the request body from the flags the user set.
func (f *entityFlags) payload(cmd *cobra.Command) (map[string]any, error) {
	out := map[string]any{}
	set := func(flag, key string, v any) {
		if cmd.Flags().Lookup(flag) != nil && cmd.Flags().Changed(flag) {
			out[key] = v
		}
	}
	set("kind", "kind", f.kind)
	set("description", "description", f.description)
	set("sponsors", "sponsors", stringsToAny(f.sponsors))
	set("state", "state", f.state)
	set("new-name", "new_name", f.newName)
	set("profile", "profile", stringMapToAny(f.profile))
	set("metadata", "metadata", stringMapToAny(f.metadata))
	if cmd.Flags().Lookup("alias") != nil && cmd.Flags().Changed("alias") {
		aliases := make([]any, 0, len(f.aliases))
		for i, raw := range f.aliases {
			mount, name, ok := strings.Cut(raw, "=")
			if !ok || mount == "" || name == "" {
				return nil, fmt.Errorf("-alias #%d must be <mount>=<name>, e.g. auth/kubernetes/=system:serviceaccount:ci:agent: %w",
					i+1, helpers.ErrUsage)
			}
			aliases = append(aliases, map[string]any{"mount": mount, "name": name})
		}
		out["aliases"] = aliases
	}
	return out, nil
}

func stringMapToAny(m map[string]string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// validateEntityName checks the positional entity name before it becomes a
// path segment. The server applies the full naming rule.
func validateEntityName(name string) error {
	return helpers.ValidateIdentifier("entity name", name)
}

// aliasesOf returns the native identities of an entity's response data.
func aliasesOf(v any) []map[string]any {
	switch t := v.(type) {
	case []any:
		out := make([]map[string]any, 0, len(t))
		for _, it := range t {
			if m, ok := it.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	case []map[string]any:
		return t
	}
	return nil
}

// aliasCell renders one native identity as "<mount>  <name>"; a mount
// disabled since shows by accessor.
func aliasCell(a map[string]any) string {
	mount := cell(a["mount"])
	if mount == "" {
		mount = cell(a["mount_accessor"]) + " (mount gone)"
	}
	return mount + "  " + cell(a["name"])
}

// printEntityTable renders one entity's response data as a key/value table,
// one row per native identity. Empty optional fields are left out; warnings
// go to stderr through PrintWarnings.
func printEntityTable(data map[string]any) {
	rows := [][]any{{"Name", cell(data["name"])}}
	add := func(label string, v any) {
		if s := cell(v); s != "" {
			rows = append(rows, []any{label, s})
		}
	}
	add("ID", data["id"])
	add("Kind", data["kind"])
	add("State", data["state"])
	if gb := cell(data["governed_by"]); gb != "" {
		rows = append(rows, []any{"Governed By", gb})
	} else {
		rows = append(rows, []any{"Governed By", "(ungoverned: " + cell(data["ungoverned_reason"]) + ")"})
	}
	add("Description", data["description"])
	add("Sponsors", data["sponsors"])
	add("Profile", data["profile"])
	add("Metadata", data["metadata"])
	for i, a := range aliasesOf(data["aliases"]) {
		label := ""
		if i == 0 {
			label = "Aliases"
		}
		rows = append(rows, []any{label, aliasCell(a)})
	}
	add("Hash", data["hash"])
	add("Created At", data["created_at"])
	add("Updated At", data["updated_at"])
	helpers.PrintTable([]string{"Key", "Value"}, rows)
}

// renderEntityWrite prints the entity a create or update returned, with its
// warnings on stderr. marker ("created" or "updated") is set true in the
// rendered envelope.
func renderEntityWrite(resource *api.Resource, name, marker string) error {
	out := map[string]any{}
	var resData map[string]any
	if resource != nil {
		resData = resource.Data
	}
	helpers.MergeServerResponseInto(out, resData, map[string]any{
		"name": name,
		marker: true,
	})
	helpers.PrintWarnings(helpers.WarningsFromData(resData))
	return helpers.RenderMap(out, func() {
		printEntityTable(out)
	})
}
