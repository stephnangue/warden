//go:build e2e

package audit

import (
	"encoding/json"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// TestJSON_AuditEnableDryRun exercises `warden audit enable --json` with
// --dry-run. We dry-run instead of really enabling because:
//
//   - audit-enable opens a file handle on the configured path and the
//     node's filesystem won't necessarily allow that under the e2e
//     fixture without ceremony,
//   - the surface we want to verify here is the CLI plumbing — schema
//     fetch, payload validation, no real request — not the audit
//     subsystem itself (already covered in audit_test.go).
func TestJSON_AuditEnableDryRun(t *testing.T) {
	port := h.GetLeaderPort(t)

	out, err := h.WardenCLIWithPort(t, port, map[string]string{
		"WARDEN_TOKEN": h.RootToken(t),
	}, "audit", "enable", "e2e-json-audit",
		"--json", `{"type":"file","description":"e2e --json audit","config":{"file_path":"/tmp/e2e-json-audit.log","format":"json"}}`,
		"--dry-run",
		"-o", "json")
	if err != nil {
		t.Fatalf("audit enable --json --dry-run failed: %v\nOutput:\n%s", err, out)
	}

	var resp map[string]any
	if jsonErr := json.Unmarshal([]byte(out), &resp); jsonErr != nil {
		t.Fatalf("output not JSON: %v\n%s", jsonErr, out)
	}
	if resp["dry_run"] != true || resp["validated"] != true {
		t.Errorf("expected dry_run=true and validated=true; got %v", resp)
	}
}
