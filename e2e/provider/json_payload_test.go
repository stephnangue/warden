//go:build e2e

package provider

import (
	"encoding/json"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// TestJSON_ProviderEnableDryRun exercises `warden provider enable --json`
// with --dry-run. Real-mount tests would conflict with the `vault`
// provider already configured by setup.sh; dry-run verifies the CLI
// plumbing (schema fetch, payload validation, exclusivity check) without
// touching mount-table state.
func TestJSON_ProviderEnableDryRun(t *testing.T) {
	port := h.GetLeaderPort(t)

	out, err := h.WardenCLIWithPort(t, port, map[string]string{
		"WARDEN_TOKEN": h.RootToken(t),
	}, "provider", "enable", "e2e-json-provider",
		"--json", `{"type":"vault","description":"e2e --json provider"}`,
		"--dry-run",
		"-o", "json")
	if err != nil {
		t.Fatalf("provider enable --json --dry-run failed: %v\nOutput:\n%s", err, out)
	}

	var resp map[string]any
	if jsonErr := json.Unmarshal([]byte(out), &resp); jsonErr != nil {
		t.Fatalf("output not JSON: %v\n%s", jsonErr, out)
	}
	if resp["dry_run"] != true || resp["validated"] != true {
		t.Errorf("expected dry_run=true and validated=true; got %v", resp)
	}
}

// TestJSON_ProviderEnableRejectsTypedFlagConflict pins the mutual-exclusivity
// rule at the provider command — agents that mix --type with --json should
// fail fast with a usage error.
func TestJSON_ProviderEnableRejectsTypedFlagConflict(t *testing.T) {
	port := h.GetLeaderPort(t)

	out, err := h.WardenCLIWithPort(t, port, map[string]string{
		"WARDEN_TOKEN": h.RootToken(t),
	}, "provider", "enable", "e2e-conflict",
		"--type", "vault",
		"--json", `{"type":"vault"}`,
		"-o", "json")
	if err == nil {
		t.Fatalf("expected non-zero exit for conflicting flags; got success.\nOutput:\n%s", out)
	}
}

// TestJSON_ProviderEnableWithPathFlagDryRun verifies that -path works on
// provider enable. Uses Vault-style single-dash long flags so this test
// also exercises the flag-normalization layer against the newly-added
// -path flag.
func TestJSON_ProviderEnableWithPathFlagDryRun(t *testing.T) {
	port := h.GetLeaderPort(t)

	out, err := h.WardenCLIWithPort(t, port, map[string]string{
		"WARDEN_TOKEN": h.RootToken(t),
	}, "provider", "enable",
		"-type", "vault",
		"-path", "e2e-pathflag-provider",
		"-dry-run",
		"-o", "json")
	if err != nil {
		t.Fatalf("provider enable -path -dry-run failed: %v\nOutput:\n%s", err, out)
	}

	var resp map[string]any
	if jsonErr := json.Unmarshal([]byte(out), &resp); jsonErr != nil {
		t.Fatalf("output not JSON: %v\n%s", jsonErr, out)
	}
	if resp["dry_run"] != true || resp["validated"] != true {
		t.Errorf("expected dry_run=true and validated=true; got %v", resp)
	}
}

// TestJSON_ProviderEnableRejectsPathAndPositionalConflict pins the conflict
// rule: supplying both -path and a positional PATH must fail with a usage
// error.
func TestJSON_ProviderEnableRejectsPathAndPositionalConflict(t *testing.T) {
	port := h.GetLeaderPort(t)

	out, err := h.WardenCLIWithPort(t, port, map[string]string{
		"WARDEN_TOKEN": h.RootToken(t),
	}, "provider", "enable", "positional-path",
		"-type", "vault",
		"-path", "flag-path",
		"-o", "json")
	if err == nil {
		t.Fatalf("expected non-zero exit for -path + positional PATH; got success.\nOutput:\n%s", out)
	}
}
