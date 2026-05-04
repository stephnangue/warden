package helpers

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/mattn/go-isatty"
)

type Format string

const (
	FormatTable  Format = "table"
	FormatJSON   Format = "json"
	FormatNDJSON Format = "ndjson"
	FormatText   Format = "text"
)

// Persistent flag values populated by cmd/warden.go via the pointer accessors.
var (
	outputFlag string
	fieldsFlag string
)

func OutputFlagPtr() *string { return &outputFlag }
func FieldsFlagPtr() *string { return &fieldsFlag }

// SetOutputFormat overrides the resolved format. Intended for tests.
func SetOutputFormat(f string) { outputFlag = f }

// SetFields overrides the field-projection list. Intended for tests.
func SetFields(s string) { fieldsFlag = s }

// outWriter / errWriter are the rendering destinations. Production code uses
// os.Stdout / os.Stderr; tests swap them via SetOutputWriter / SetErrorWriter.
var (
	outWriter io.Writer = os.Stdout
	errWriter io.Writer = os.Stderr
)

// SetOutputWriter overrides stdout. Intended for tests.
func SetOutputWriter(w io.Writer) { outWriter = w }

// SetErrorWriter overrides stderr. Intended for tests.
func SetErrorWriter(w io.Writer) { errWriter = w }

// ResetWriters restores stdout/stderr to the process streams. Intended for tests.
func ResetWriters() {
	outWriter = os.Stdout
	errWriter = os.Stderr
}

// ResolveFormat returns the effective output format. Resolution order:
// explicit --output flag, then $WARDEN_OUTPUT, then TTY autodetect (table on
// terminal, json otherwise).
func ResolveFormat() Format {
	if outputFlag != "" {
		return Format(strings.ToLower(outputFlag))
	}
	if env := os.Getenv("WARDEN_OUTPUT"); env != "" {
		return Format(strings.ToLower(env))
	}
	if isatty.IsTerminal(os.Stdout.Fd()) || isatty.IsCygwinTerminal(os.Stdout.Fd()) {
		return FormatTable
	}
	return FormatJSON
}

// ResolveFields returns the parsed list of dot-paths from --fields or
// $WARDEN_FIELDS. Returns nil when no projection is requested.
func ResolveFields() []string {
	raw := fieldsFlag
	if raw == "" {
		raw = os.Getenv("WARDEN_FIELDS")
	}
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// ValidateFormat returns an error for unknown format values.
func ValidateFormat(f Format) error {
	switch f {
	case FormatTable, FormatJSON, FormatNDJSON, FormatText:
		return nil
	default:
		return fmt.Errorf("unknown output format: %q (must be one of: table, json, ndjson, text)", string(f))
	}
}

// RenderMap emits a single map at the resolved format. tableFn renders the
// table form; pass nil to fall back to PrintMapAsTable. Field projection is
// applied to all non-table formats; in table mode with --fields set, the
// bespoke tableFn is bypassed in favor of a generic projected key/value table.
func RenderMap(data map[string]any, tableFn func()) error {
	format := ResolveFormat()
	if err := ValidateFormat(format); err != nil {
		return err
	}

	fields := ResolveFields()

	if format == FormatTable {
		if fields != nil {
			fmt.Fprintln(errWriter, "warning: --fields with table output uses a generic key/value layout; use -o json for the structured form")
			PrintMapAsTable(ProjectMap(data, fields))
			return nil
		}
		if tableFn != nil {
			tableFn()
		} else if data != nil {
			PrintMapAsTable(data)
		}
		return nil
	}

	if fields != nil {
		data = ProjectMap(data, fields)
	}

	switch format {
	case FormatJSON:
		return writeJSON(outWriter, data, true)
	case FormatNDJSON:
		return writeJSON(outWriter, data, false)
	case FormatText:
		return writeText(outWriter, data)
	}
	return nil
}

// RenderList emits a slice of records at the resolved format. tableFn renders
// the table form (and is responsible for any "no items" message in table mode
// when items is empty). Field projection is applied to non-table formats; in
// table mode with --fields set, the bespoke tableFn is bypassed in favor of a
// projected per-column table.
func RenderList(items []map[string]any, tableFn func()) error {
	format := ResolveFormat()
	if err := ValidateFormat(format); err != nil {
		return err
	}

	fields := ResolveFields()

	if format == FormatTable {
		if fields != nil {
			fmt.Fprintln(errWriter, "warning: --fields with table output uses a generic projected layout; use -o json for the structured form")
			renderProjectedListTable(items, fields)
			return nil
		}
		if tableFn != nil {
			tableFn()
		}
		return nil
	}

	if fields != nil {
		projected := make([]map[string]any, len(items))
		for i, item := range items {
			projected[i] = ProjectMap(item, fields)
		}
		items = projected
	}

	// Ensure JSON emits "[]" instead of "null" when the slice is nil.
	if items == nil {
		items = []map[string]any{}
	}

	switch format {
	case FormatJSON:
		return writeJSON(outWriter, items, true)
	case FormatNDJSON:
		for _, item := range items {
			if err := writeJSON(outWriter, item, false); err != nil {
				return err
			}
		}
		return nil
	case FormatText:
		for _, item := range items {
			if err := writeText(outWriter, item); err != nil {
				return err
			}
		}
		return nil
	}
	return nil
}

// RenderStrings emits a list of plain strings (e.g. policy names, list keys)
// at the resolved format. tableFn renders the table form. --fields is ignored
// since strings have no fields to project.
func RenderStrings(items []string, tableFn func()) error {
	format := ResolveFormat()
	if err := ValidateFormat(format); err != nil {
		return err
	}

	if format == FormatTable {
		if tableFn != nil {
			tableFn()
		}
		return nil
	}

	if items == nil {
		items = []string{}
	}

	switch format {
	case FormatJSON:
		return writeJSON(outWriter, items, true)
	case FormatNDJSON:
		for _, s := range items {
			fmt.Fprintln(outWriter, s)
		}
		return nil
	case FormatText:
		for _, s := range items {
			fmt.Fprintln(outWriter, s)
		}
		return nil
	}
	return nil
}

func writeJSON(w io.Writer, v any, pretty bool) error {
	var (
		b   []byte
		err error
	)
	if pretty {
		b, err = json.MarshalIndent(v, "", "  ")
	} else {
		b, err = json.Marshal(v)
	}
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}
	_, err = fmt.Fprintln(w, string(b))
	return err
}

func writeText(w io.Writer, data map[string]any) error {
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", k, logfmtValue(data[k])))
	}
	_, err := fmt.Fprintln(w, strings.Join(parts, " "))
	return err
}

// logfmtValue renders a value in logfmt style: bare for simple tokens, quoted
// (with backslash-escaped quotes and backslashes) when the value contains
// whitespace, `=`, or `"`. This keeps `-o text` output line-parseable.
func logfmtValue(v any) string {
	if v == nil {
		return ""
	}
	s := fmt.Sprintf("%v", v)
	if !needsQuoting(s) {
		return s
	}
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func needsQuoting(s string) bool {
	if s == "" {
		return true
	}
	for _, r := range s {
		if r == ' ' || r == '\t' || r == '\n' || r == '"' || r == '=' || r == '\\' {
			return true
		}
	}
	return false
}

// renderProjectedListTable prints a table with one column per requested field
// and one row per record, used when --fields is set in table mode.
func renderProjectedListTable(items []map[string]any, fields []string) {
	if len(items) == 0 {
		fmt.Fprintln(outWriter, "No data to display")
		return
	}
	headers := append([]string{}, fields...)
	rows := make([][]any, 0, len(items))
	for _, item := range items {
		row := make([]any, 0, len(fields))
		for _, f := range fields {
			row = append(row, projectForCell(item, f))
		}
		rows = append(rows, row)
	}
	PrintTable(headers, rows)
}

// projectForCell returns a single display value for one path applied to one
// record. Missing paths render as empty cells.
func projectForCell(item map[string]any, path string) any {
	proj, ok := project(item, strings.Split(path, "."))
	if !ok {
		return ""
	}
	return collapseForCell(proj)
}

// collapseForCell flattens a projected subtree to a display-ready value.
// Single-key chains collapse to their leaf; slices and multi-key maps join
// their values with ", " for stable cell rendering.
func collapseForCell(v any) any {
	switch x := v.(type) {
	case map[string]any:
		if len(x) == 1 {
			for _, vv := range x {
				return collapseForCell(vv)
			}
		}
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s=%v", k, collapseForCell(x[k])))
		}
		return strings.Join(parts, ", ")
	case []any:
		parts := make([]string, 0, len(x))
		for _, item := range x {
			parts = append(parts, fmt.Sprintf("%v", collapseForCell(item)))
		}
		return strings.Join(parts, ", ")
	default:
		return x
	}
}

// ProjectMap returns a new map containing only the fields named by `paths`.
// Path syntax: dot for nesting (`address.city`), `*` to match every key in a
// map or every element in a slice at that level (`tokens.*.id`). Missing paths
// are silently omitted so callers don't have to handle "field absent" specially.
func ProjectMap(src map[string]any, paths []string) map[string]any {
	out := make(map[string]any)
	for _, p := range paths {
		proj, ok := project(src, strings.Split(p, "."))
		if !ok {
			continue
		}
		projMap, ok := proj.(map[string]any)
		if !ok {
			continue
		}
		mergeMap(out, projMap)
	}
	return out
}

// project returns the projection of `src` at `segments`, plus an ok flag that
// is false when the path is unmatched (so caller can omit it cleanly).
func project(src any, segments []string) (any, bool) {
	if len(segments) == 0 {
		return src, true
	}
	seg := segments[0]
	rest := segments[1:]

	switch v := src.(type) {
	case map[string]any:
		if seg == "*" {
			out := make(map[string]any)
			for k, child := range v {
				if proj, ok := project(child, rest); ok {
					out[k] = proj
				}
			}
			if len(out) == 0 {
				return nil, false
			}
			return out, true
		}
		child, ok := v[seg]
		if !ok {
			return nil, false
		}
		proj, ok := project(child, rest)
		if !ok {
			return nil, false
		}
		return map[string]any{seg: proj}, true

	case []any:
		if seg != "*" {
			// Only `*` descends into slices; numeric indexing not supported.
			return nil, false
		}
		out := make([]any, len(v))
		anyKept := false
		for i, child := range v {
			if proj, ok := project(child, rest); ok {
				out[i] = proj
				anyKept = true
			}
		}
		if !anyKept {
			return nil, false
		}
		return out, true

	default:
		// Scalar with more segments to descend into → not matchable.
		return nil, false
	}
}

// mergeMap deep-merges src into dst. Nested maps are merged recursively;
// same-length slice-of-maps are merged element-wise.
func mergeMap(dst, src map[string]any) {
	for k, v := range src {
		existing, ok := dst[k]
		if !ok {
			dst[k] = v
			continue
		}
		switch nv := v.(type) {
		case map[string]any:
			if em, ok := existing.(map[string]any); ok {
				mergeMap(em, nv)
				continue
			}
		case []any:
			if es, ok := existing.([]any); ok && len(es) == len(nv) {
				for i := range nv {
					em, _ := es[i].(map[string]any)
					nm, _ := nv[i].(map[string]any)
					if em != nil && nm != nil {
						mergeMap(em, nm)
					} else if em == nil && nv[i] != nil {
						es[i] = nv[i]
					}
				}
				continue
			}
		}
		dst[k] = v
	}
}
