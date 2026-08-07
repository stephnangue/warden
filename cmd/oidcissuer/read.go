package oidcissuer

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
)

var (
	ReadCmd = &cobra.Command{
		Use:           "read",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Show the OIDC issuer configuration and readiness",
		Long: `
Usage: warden oidc-issuer read

  Show the current OIDC issuer configuration — enabled state, issuer URL,
  assertion TTL, signing-key rotation timings and status, where the signing key
  is held (in-process or an external KMS), publisher (secrets masked), and whether
  the issuer is ready to mint. Root namespace only.

      $ warden oidc-issuer read
`,
		Args: cobra.NoArgs,
		RunE: runRead,
	}
)

func runRead(cmd *cobra.Command, args []string) error {
	c, err := helpers.Client()
	if err != nil {
		return err
	}

	resource, err := c.Operator().Read(oidcIssuerConfigPath)
	if err != nil {
		return fmt.Errorf("error reading OIDC issuer configuration: %w", err)
	}
	if resource == nil || resource.Data == nil {
		fmt.Fprintln(os.Stderr, "No OIDC issuer configuration found.")
		return nil
	}

	return helpers.RenderMap(resource.Data, func() {
		printOIDCIssuerTable(resource.Data)
	})
}

// scalarOrder is the stable, grouped order of top-level fields (not the default global
// alphabetical sort), so related settings stay together.
var scalarOrder = []string{
	"enabled", "ready", "issuer_url",
	"assertion_ttl", "jwks_cache_ttl", "retired_key_grace", "key_rotation_period",
}

// durationScalars are top-level fields the server sends as integer seconds; they render as
// human-readable Go durations (e.g. 5m0s) rather than bare numbers.
var durationScalars = map[string]bool{
	"assertion_ttl": true, "jwks_cache_ttl": true, "retired_key_grace": true,
}

// rotationFields is the field order of the key_rotation and publisher_rotation status blocks.
var rotationFields = []string{"running", "last_rotated_at", "next_rotation", "last_error", "last_error_at"}

// publisherFields is the field order of the publisher block (type first, identity fields,
// masked secrets, rotation_period last).
var publisherFields = []string{
	"type", "dir", "base_url", "auth_header", "auth_value",
	"bucket", "region", "prefix", "access_key_id", "secret_access_key",
	"account_name", "container", "tenant_id", "client_id", "client_secret", "secret_id",
	"endpoint", "credentials_json", "rotation_period",
}

// signerFields is the field order of the signer block: where the signing key is held
// (mode) and, for an external KMS, the backend type.
var signerFields = []string{"mode", "backend"}

// printOIDCIssuerTable renders the read response as a coherent two-column table: durations
// as duration strings, and each nested block expanded into underscore-joined rows
// (publisher_type, key_rotation_next_rotation, …) instead of one crammed comma-joined cell.
// Falls back to the generic renderer for an unexpected shape.
func printOIDCIssuerTable(data map[string]any) {
	var rows [][]any
	for _, k := range scalarOrder {
		v, ok := data[k]
		if !ok {
			continue
		}
		switch {
		case k == "key_rotation_period":
			rows = append(rows, []any{k, rotationPeriodCell(v)})
		case durationScalars[k]:
			rows = append(rows, []any{k, durationCell(v)})
		default:
			rows = append(rows, []any{k, cellString(v)})
		}
	}
	rows = appendBlock(rows, data, "key_rotation", rotationFields)
	rows = appendBlock(rows, data, "publisher", publisherFields)
	rows = appendBlock(rows, data, "publisher_rotation", rotationFields)
	rows = appendBlock(rows, data, "signer", signerFields)

	if len(rows) == 0 {
		helpers.PrintMapAsTable(data)
		return
	}
	helpers.PrintTable([]string{"Key", "Value"}, rows)
}

// appendBlock expands a nested map value into one underscore-joined row per field, in the
// given order, then any unexpected keys sorted (so a field the server adds later is
// surfaced, never silently dropped).
func appendBlock(rows [][]any, data map[string]any, name string, order []string) [][]any {
	block, ok := data[name].(map[string]any)
	if !ok {
		return rows
	}
	seen := make(map[string]bool, len(order))
	for _, f := range order {
		seen[f] = true
		if v, ok := block[f]; ok {
			rows = append(rows, []any{name + "_" + f, blockValueCell(f, v)})
		}
	}
	extra := make([]string, 0)
	for f := range block {
		if !seen[f] {
			extra = append(extra, f)
		}
	}
	sort.Strings(extra)
	for _, f := range extra {
		rows = append(rows, []any{name + "_" + f, cellString(block[f])})
	}
	return rows
}

// blockValueCell formats a nested field value, normalizing a publisher rotation_period to a
// canonical duration string for consistency with the top-level durations.
func blockValueCell(field string, v any) string {
	s := cellString(v)
	if field == "rotation_period" && s != "" {
		if d, err := time.ParseDuration(s); err == nil {
			return d.String()
		}
	}
	return s
}

// rotationPeriodCell renders key_rotation_period: 0 seconds means automatic rotation is off.
func rotationPeriodCell(v any) string {
	if secs, ok := toSeconds(v); ok && secs == 0 {
		return "disabled"
	}
	return durationCell(v)
}

// durationCell renders a seconds value as a Go duration string; passes through otherwise.
func durationCell(v any) string {
	if secs, ok := toSeconds(v); ok {
		return (time.Duration(secs) * time.Second).String()
	}
	return cellString(v)
}

// cellString renders any JSON-decoded scalar (json.Number, bool, string) for a table cell.
func cellString(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}

// toSeconds extracts an integer seconds value from a JSON-decoded number.
func toSeconds(v any) (int64, bool) {
	switch n := v.(type) {
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return i, true
		}
	case float64:
		return int64(n), true
	case int64:
		return n, true
	case int:
		return int64(n), true
	}
	return 0, false
}
