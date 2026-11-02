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
// an empty one (e.g. -description="") clears it. -kind and -alias are create
// only, -new-name update only. The sponsor and the state change through
// commands of their own ('entity sponsor', 'entity state').
type entityFlags struct {
	kind        string
	description string
	profile     map[string]string
	metadata    map[string]string
	aliases     []string
	newName     string
}

// entityFlagNames maps each typed flag to the payload key it sets.
var entityFlagNames = []struct{ flag, key string }{
	{"kind", "kind"},
	{"description", "description"},
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

// sponsorGroup names a sponsor of an entity's response data by its group,
// qualified with its namespace ("/billing-leads", "team-a/billing-leads"), or
// "" when the entity has none.
func sponsorGroup(v any) string {
	sp, ok := v.(map[string]any)
	if !ok {
		return ""
	}
	ns := cell(sp["namespace"])
	if ns == "" || ns == "/" {
		return "/" + cell(sp["group"])
	}
	return ns + cell(sp["group"])
}

// sponsorActorCell renders who proposed or accepted a sponsor: "<mount>
// <alias>" for a person, the principal alone for a token no mount issued.
func sponsorActorCell(v any) string {
	a, ok := v.(map[string]any)
	if !ok {
		return ""
	}
	if alias := cell(a["alias"]); alias != "" {
		mount := cell(a["mount"])
		if mount == "" {
			mount = cell(a["mount_accessor"])
		}
		return mount + " " + alias
	}
	return cell(a["principal"])
}

// sponsorCell renders a sponsor ("/billing-leads  accepted by auth/oidc/
// 0583c1a7-…") or a pending handover ("/finance-oncall  proposed by …").
func sponsorCell(v any) string {
	g := sponsorGroup(v)
	if g == "" {
		return ""
	}
	sp := v.(map[string]any)
	if by := sponsorActorCell(sp["accepted_by"]); by != "" {
		return g + "  accepted by " + by
	}
	return g + "  proposed by " + sponsorActorCell(sp["added_by"])
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
	add("Sponsor", sponsorCell(data["sponsor"]))
	add("Pending Sponsor", sponsorCell(data["pending_sponsor"]))
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
