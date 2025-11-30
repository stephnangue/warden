package helpers

import (
	"fmt"
	"os"

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
		WithRow(" ").
		WithColumn(" ").
		WithTopLeft("").
		WithTopMid(" ").
		WithTopRight(" ").
		WithMidLeft(" ").
		WithCenter(" ").
		WithMidRight(" ").
		WithBottomLeft(" ").
		WithBottomMid(" ").
		WithBottomRight(" ")

	rd := tw.Rendition{Symbols: symbols}
	rd.Settings.Lines.ShowHeaderLine = tw.Off

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
// with "Key" and "Value" headers
func PrintMapAsTable(mapData map[string]any) {
	if len(mapData) == 0 {
		fmt.Println("No data to display")
		return
	}

	var data [][]any
	for key, value := range mapData {
		data = append(data, []any{key, value})
	}
	PrintTable([]string{"Key", "Value"}, data)
}
