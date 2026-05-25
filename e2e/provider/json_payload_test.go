//go:build e2e

package provider

import (
	"encoding/json"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// TestJSON_ProviderEnableDryRun exercises `warden provider enable -json`
// with -dry-run. Real-mount tests would conflict with the `vault` provider
// already configured by setup.sh; dry-run verifies the CLI plumbing
// (schema fetch, payload validation, exclusivity check) without touching
// mount-table state.
func TestJSON_ProviderEnableDryRun(t *testing.T) {
	port := h.GetLeaderPort(t)

	out, err := h.WardenCLIWithPort(t, port, map[string]string{
		"WARDEN_TOKEN": h.RootToken(t),
	}, "provider", "enable", "vault",
		"-path", "e2e-json-provider",
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

// TestJSON_ProviderEnableRejectsDescriptionWithJSON pins the mutual-
// exclusivity rule — agents that mix -description with -json should fail
// fast with a usage error.
func TestJSON_ProviderEnableRejectsDescriptionWithJSON(t *testing.T) {
	port := h.GetLeaderPort(t)

	out, err := h.WardenCLIWithPort(t, port, map[string]string{
		"WARDEN_TOKEN": h.RootToken(t),
	}, "provider", "enable", "vault",
		"-description", "should-not-be-allowed",
		"--json", `{"type":"vault"}`,
		"-o", "json")
	if err == nil {
		t.Fatalf("expected non-zero exit for conflicting flags; got success.\nOutput:\n%s", out)
	}
}

// TestJSON_ProviderEnableWithPathFlagDryRun verifies that -path overrides
// the default mount path. Uses Vault-style single-dash long flags so this
// test also exercises the flag-normalization layer against the -path flag.
func TestJSON_ProviderEnableWithPathFlagDryRun(t *testing.T) {
	port := h.GetLeaderPort(t)

	out, err := h.WardenCLIWithPort(t, port, map[string]string{
		"WARDEN_TOKEN": h.RootToken(t),
	}, "provider", "enable",
		"-path", "e2e-pathflag-provider",
		"-dry-run",
		"-o", "json",
		"vault")
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

// TestJSON_ProviderEnableRejectsPayloadTypeMismatch pins the conflict rule:
// when the JSON payload's "type" field disagrees with the TYPE positional,
// the CLI must fail with a usage error.
func TestJSON_ProviderEnableRejectsPayloadTypeMismatch(t *testing.T) {
	port := h.GetLeaderPort(t)

	out, err := h.WardenCLIWithPort(t, port, map[string]string{
		"WARDEN_TOKEN": h.RootToken(t),
	}, "provider", "enable", "vault",
		"--json", `{"type":"aws"}`,
		"-o", "json")
	if err == nil {
		t.Fatalf("expected non-zero exit for TYPE/payload mismatch; got success.\nOutput:\n%s", out)
	}
}
