package identity

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
)

// groupFlags are the typed flags create and update share. Only the flags the
// user set are sent, so on update an omitted flag keeps the stored value and
// an empty one (e.g. -roles="") clears it.
type groupFlags struct {
	typ         string
	description string
	roles       []string
	rules       []string
	validUntil  string
	metadata    map[string]string
}

// groupFlagNames maps each typed flag to the payload key it sets.
var groupFlagNames = []struct{ flag, key string }{
	{"type", "type"},
	{"description", "description"},
	{"roles", "roles"},
	{"rule", "rules"},
	{"valid-until", "valid_until"},
	{"metadata", "metadata"},
}

func (f *groupFlags) bind(cmd *cobra.Command) {
	fs := cmd.Flags()
	fs.StringVar(&f.typ, "type", "", `Where membership comes from: "virtual" (required on create; never changes)`)
	fs.StringVar(&f.description, "description", "", "What the group is for")
	fs.StringSliceVar(&f.roles, "roles", nil, "Roles membership grants (repeat or comma-separated)")
	fs.StringArrayVar(&f.rules, "rule", nil,
		`One rule as a JSON object of selectors, each a fact name with its values (a list, or one string), `+
			`including "mount", e.g. '{"mount": "auth/kubernetes/", "workload": ["ci", "cd"]}' (repeatable; any one rule matching makes a member)`)
	fs.StringVar(&f.validUntil, "valid-until", "",
		`RFC 3339 instant after which the group grants nothing, e.g. 2026-12-31T23:59:59Z (on update, "" clears it)`)
	fs.StringToStringVar(&f.metadata, "metadata", nil, "Free-form label (key=value, repeatable)")
}

// reset restores the zero values. Intended for tests, which reuse the
// package-level commands.
func (f *groupFlags) reset() { *f = groupFlags{} }

func (f *groupFlags) changed(cmd *cobra.Command) map[string]bool {
	out := make(map[string]bool, len(groupFlagNames))
	for _, n := range groupFlagNames {
		out["-"+n.flag] = cmd.Flags().Changed(n.flag)
	}
	return out
}

// payload builds the request body from the flags the user set.
func (f *groupFlags) payload(cmd *cobra.Command) (map[string]any, error) {
	out := map[string]any{}
	set := func(flag, key string, v any) {
		if cmd.Flags().Changed(flag) {
			out[key] = v
		}
	}
	set("type", "type", f.typ)
	set("description", "description", f.description)
	set("roles", "roles", stringsToAny(f.roles))
	set("valid-until", "valid_until", f.validUntil)
	if cmd.Flags().Changed("metadata") {
		md := make(map[string]any, len(f.metadata))
		for k, v := range f.metadata {
			md[k] = v
		}
		out["metadata"] = md
	}
	if cmd.Flags().Changed("rule") {
		rules := make([]any, 0, len(f.rules))
		for i, raw := range f.rules {
			var r map[string]any
			if err := json.Unmarshal([]byte(raw), &r); err != nil {
				return nil, fmt.Errorf("-rule #%d is not a JSON object: %v: %w", i+1, err, helpers.ErrUsage)
			}
			rules = append(rules, r)
		}
		out["rules"] = rules
	}
	return out, nil
}

func stringsToAny(s []string) []any {
	out := make([]any, 0, len(s))
	for _, v := range s {
		out = append(out, v)
	}
	return out
}

// validateGroupName checks the positional group name before it becomes a
// path segment. The server applies the full naming rule.
func validateGroupName(name string) error {
	return helpers.ValidateIdentifier("group name", name)
}

// formatRule renders one rule on one line, a selector at a time: "mount"
// first, then the others sorted by name, each as name=v1|v2.
func formatRule(s map[string]any) string {
	names := make([]string, 0, len(s))
	for k := range s {
		if k != "mount" {
			names = append(names, k)
		}
	}
	sort.Strings(names)
	if _, ok := s["mount"]; ok {
		names = append([]string{"mount"}, names...)
	}
	parts := make([]string, 0, len(names))
	for _, n := range names {
		var vals []string
		switch vs := s[n].(type) {
		case []any:
			for _, v := range vs {
				vals = append(vals, fmt.Sprint(v))
			}
		case []string:
			vals = vs
		default:
			vals = []string{fmt.Sprint(vs)}
		}
		parts = append(parts, n+"="+strings.Join(vals, "|"))
	}
	return strings.Join(parts, "  ")
}

// rulesOf returns the rules of a group's response data as maps.
func rulesOf(v any) []map[string]any {
	switch t := v.(type) {
	case []any:
		out := make([]map[string]any, 0, len(t))
		for _, it := range t {
			if m, ok := it.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	case []map[string][]string:
		out := make([]map[string]any, 0, len(t))
		for _, s := range t {
			m := make(map[string]any, len(s))
			for k, vs := range s {
				m[k] = vs
			}
			out = append(out, m)
		}
		return out
	}
	return nil
}

// printGroupTable renders one group's response data as a key/value table,
// one row per rule ("#i  mount=…  name=v1|v2"), then the group's rule and
// selector counts. Empty optional fields are left out; warnings go to stderr
// through PrintWarnings.
func printGroupTable(data map[string]any) {
	rows := [][]any{{"Name", cell(data["name"])}}
	add := func(label string, v any) {
		if s := cell(v); s != "" {
			rows = append(rows, []any{label, s})
		}
	}
	add("ID", data["id"])
	add("Type", data["type"])
	add("Description", data["description"])
	add("Roles", data["roles"])
	for i, r := range rulesOf(data["rules"]) {
		label := ""
		if i == 0 {
			label = "Rules"
		}
		rows = append(rows, []any{label, fmt.Sprintf("#%d  %s", i, formatRule(r))})
	}
	add("Rule Count", data["rule_count"])
	add("Selector Count", data["selector_count"])
	add("Valid Until", data["valid_until"])
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

// renderGroupWrite prints the group a create or update returned, with its
// warnings on stderr. marker ("created" or "updated") is set true in the
// rendered envelope.
func renderGroupWrite(resource *api.Resource, name, marker string) error {
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
		printGroupTable(out)
	})
}
