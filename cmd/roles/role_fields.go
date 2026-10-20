package roles

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

// roleFlags are the typed flags create and update share. Only the flags the
// user set are sent, so on update an omitted flag keeps the stored value and
// an empty one (e.g. -cred-spec-name="") clears it.
type roleFlags struct {
	description  string
	policies     []string
	credSpecName string
	skill        string
	providerPath string
	metadata     map[string]string
}

// roleFlagNames maps each typed flag to the payload key it sets.
var roleFlagNames = []struct{ flag, key string }{
	{"description", "description"},
	{"policies", "policies"},
	{"cred-spec-name", "cred_spec_name"},
	{"skill", "skill"},
	{"provider-path", "provider_path"},
	{"metadata", "metadata"},
}

func (f *roleFlags) bind(cmd *cobra.Command) {
	fs := cmd.Flags()
	fs.StringVar(&f.description, "description", "", "What the role is for, shown to agents by discovery")
	fs.StringSliceVar(&f.policies, "policies", nil, "Policies a caller running under the role holds (repeat or comma-separated)")
	fs.StringVar(&f.credSpecName, "cred-spec-name", "", "Credential spec a caller running under the role is served")
	fs.StringVar(&f.skill, "skill", "", "Skill that teaches an agent to use the role")
	fs.StringVar(&f.providerPath, "provider-path", "", "Mount path of the provider the role is used with (e.g. aws/)")
	fs.StringToStringVar(&f.metadata, "metadata", nil, "Free-form label (key=value, repeatable)")
}

// reset restores the zero values. Intended for tests, which reuse the
// package-level commands.
func (f *roleFlags) reset() { *f = roleFlags{} }

// changed reports, per flag as the user types it, whether it was set.
func (f *roleFlags) changed(cmd *cobra.Command) map[string]bool {
	out := make(map[string]bool, len(roleFlagNames))
	for _, n := range roleFlagNames {
		out["-"+n.flag] = cmd.Flags().Changed(n.flag)
	}
	return out
}

// payload builds the request body from the flags the user set.
func (f *roleFlags) payload(cmd *cobra.Command) map[string]any {
	values := map[string]any{
		"description":    f.description,
		"policies":       stringsToAny(f.policies),
		"cred_spec_name": f.credSpecName,
		"skill":          f.skill,
		"provider_path":  f.providerPath,
		"metadata":       stringMapToAny(f.metadata),
	}
	out := map[string]any{}
	for _, n := range roleFlagNames {
		if cmd.Flags().Changed(n.flag) {
			out[n.key] = values[n.key]
		}
	}
	return out
}

// stringsToAny returns s as a JSON-shaped list, empty rather than nil, so an
// explicitly empty -policies clears the policies.
func stringsToAny(s []string) []any {
	out := make([]any, 0, len(s))
	for _, v := range s {
		out = append(out, v)
	}
	return out
}

func stringMapToAny(m map[string]string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// validateRoleName checks the positional role name before it becomes a path
// segment. The server applies the full naming rule.
func validateRoleName(name string) error {
	return helpers.ValidateIdentifier("role name", name)
}

// printRoleTable renders one role's response data as a key/value table. Empty
// optional fields are left out; warnings go to stderr through PrintWarnings.
func printRoleTable(data map[string]any) {
	rows := [][]any{{"Name", cell(data["name"])}}
	add := func(label string, v any) {
		if s := cell(v); s != "" {
			rows = append(rows, []any{label, s})
		}
	}
	add("Description", data["description"])
	add("Policies", data["policies"])
	add("Cred Spec", data["cred_spec_name"])
	add("Skill", data["skill"])
	add("Provider Path", data["provider_path"])
	add("Metadata", data["metadata"])
	add("Hash", data["hash"])
	add("Created At", data["created_at"])
	add("Updated At", data["updated_at"])
	helpers.PrintTable([]string{"Key", "Value"}, rows)
}

// cell renders a response value for a table cell: lists comma-joined, maps as
// sorted key=value pairs.
func cell(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case []any:
		parts := make([]string, 0, len(t))
		for _, it := range t {
			parts = append(parts, fmt.Sprintf("%v", it))
		}
		return strings.Join(parts, ", ")
	case []string:
		return strings.Join(t, ", ")
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s=%v", k, t[k]))
		}
		return strings.Join(parts, " ")
	default:
		return fmt.Sprintf("%v", t)
	}
}
