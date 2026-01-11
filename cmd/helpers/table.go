package helpers

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/renderer"
	"github.com/olekukonko/tablewriter/tw"
)

// PrintTable prints data in a formatted table similar to Vault CLI
// headers: column headers for the table (e.g., []string{"Key", "Value"})
// data: rows of data where each row is a slice of any type (e.g., [][]any{{"key1", "value1"}, {"key2", "value2"}})
func PrintTable(headers []string, data [][]any) {
	if len(data) == 0 {
		fmt.Println("No data to display")
		return
	}

	cnf := tablewriter.Config{
		Header: tw.CellConfig{
			Alignment: tw.CellAlignment{Global: tw.AlignLeft},
		},
		Row: tw.CellConfig{
			Merging:   tw.CellMerging{Mode: tw.MergeHierarchical},
			Alignment: tw.CellAlignment{Global: tw.AlignLeft},
		},
		Debug: false,
	}

	symbols := tw.NewSymbolCustom("Warden").
		WithRow("-").
		WithTopLeft(" ").
		WithTopMid(" ").
		WithTopRight(" ").
		WithMidLeft(" ").
		WithCenter(" ").
		WithMidRight(" ").
		WithBottomLeft(" ").
		WithBottomMid(" ").
		WithBottomRight(" ")

	rd := tw.Rendition{Symbols: symbols}
	rd.Settings.Lines.ShowHeaderLine = tw.On
	rd.Settings.Lines.ShowBottom = tw.Off
	rd.Settings.Lines.ShowTop = tw.Off

	table := tablewriter.NewTable(os.Stdout,
		tablewriter.WithRenderer(renderer.NewBlueprint(rd)),
		tablewriter.WithConfig(cnf),
	)

	// Convert headers to []any for the table.Header method
	headerAny := make([]any, len(headers))
	for i, h := range headers {
		headerAny[i] = h
	}
	table.Header(headerAny...)
	table.Bulk(data)
	table.Render()
}

// PrintMapAsTable is a convenience function that prints a map as a two-column table
// with "Key" and "Value" headers. Keys are sorted alphabetically for consistent output.
func PrintMapAsTable(mapData map[string]any) {
	if len(mapData) == 0 {
		fmt.Println("No data to display")
		return
	}

	// Sort keys alphabetically for consistent output
	keys := make([]string, 0, len(mapData))
	for key := range mapData {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var data [][]any
	for _, key := range keys {
		data = append(data, []any{key, formatValue(mapData[key])})
	}
	PrintTable([]string{"Key", "Value"}, data)
}

// formatValue converts a value to a display-friendly string.
// Slices are formatted as comma-separated values, maps are formatted as key=value pairs.
func formatValue(v any) string {
	if v == nil {
		return ""
	}

	switch val := v.(type) {
	case []string:
		return strings.Join(val, ", ")
	case []any:
		parts := make([]string, 0, len(val))
		for _, item := range val {
			parts = append(parts, fmt.Sprintf("%v", item))
		}
		return strings.Join(parts, ", ")
	case map[string]any:
		parts := make([]string, 0, len(val))
		for k, v := range val {
			parts = append(parts, fmt.Sprintf("%s=%v", k, v))
		}
		sort.Strings(parts)
		return strings.Join(parts, ", ")
	default:
		return fmt.Sprintf("%v", v)
	}
}
