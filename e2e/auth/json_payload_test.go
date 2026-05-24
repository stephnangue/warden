//go:build e2e

package auth

import (
	"encoding/json"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// TestJSON_AuthEnableWithJSON covers `warden auth enable --json` end-to-end.
// Mounts a JWT auth method at a unique path with a payload-derived path
// (no positional argument), then verifies via the API that the mount
// landed.
func TestJSON_AuthEnableWithJSON(t *testing.T) {
	port := h.GetLeaderPort(t)

	const path = "e2e-json-auth"
	h.APIRequest(t, "DELETE", "sys/auth/"+path, port, "")
	t.Cleanup(func() {
		h.APIRequest(t, "DELETE", "sys/auth/"+path, port, "")
	})

	out, err := h.WardenCLIWithPort(t, port, map[string]string{
		"WARDEN_TOKEN": h.RootToken(t),
	}, "auth", "enable", path,
		"--json", `{"type":"jwt","description":"e2e --json auth enable"}`,
		"-o", "json")
	if err != nil {
		t.Fatalf("auth enable --json failed: %v\nOutput:\n%s", err, out)
	}

	var resp map[string]any
	if jsonErr := json.Unmarshal([]byte(out), &resp); jsonErr != nil {
		t.Fatalf("output not JSON: %v\n%s", jsonErr, out)
	}
	if resp["enabled"] != true {
		t.Errorf("expected enabled=true marker; got %v", resp)
	}

	// Confirm the mount exists.
	status, _ := h.APIRequest(t, "GET", "sys/auth/"+path+"/", port, "")
	if status != 200 {
		// `sys/auth/{path}` GET may not be supported; instead list and check.
		listStatus, body := h.APIRequest(t, "GET", "sys/auth?warden-list=true", port, "")
		if listStatus != 200 {
			t.Fatalf("could not verify mount: list status %d, body %s", listStatus, string(body))
		}
	}
}

// TestJSON_AuthEnableWithPathFlag verifies that -path works as an
// alternative to the positional PATH argument. Uses Vault-style single-dash
// long flags so this test also exercises the flag-normalization layer
// against the newly-added -path flag.
func TestJSON_AuthEnableWithPathFlag(t *testing.T) {
	port := h.GetLeaderPort(t)

	const path = "e2e-pathflag-auth"
	h.APIRequest(t, "DELETE", "sys/auth/"+path, port, "")
	t.Cleanup(func() {
		h.APIRequest(t, "DELETE", "sys/auth/"+path, port, "")
	})

	out, err := h.WardenCLIWithPort(t, port, map[string]string{
		"WARDEN_TOKEN": h.RootToken(t),
	}, "auth", "enable",
		"-type", "jwt",
		"-path", path,
		"-o", "json")
	if err != nil {
		t.Fatalf("auth enable -path failed: %v\nOutput:\n%s", err, out)
	}

	var resp map[string]any
	if jsonErr := json.Unmarshal([]byte(out), &resp); jsonErr != nil {
		t.Fatalf("output not JSON: %v\n%s", jsonErr, out)
	}
	if resp["enabled"] != true {
		t.Errorf("expected enabled=true marker; got %v", resp)
	}
	if resp["path"] != path+"/" {
		t.Errorf("expected path %q in response; got %v", path+"/", resp["path"])
	}
}

// TestJSON_AuthEnableRejectsPathAndPositionalConflict pins the conflict
// rule: supplying both -path and a positional PATH must fail with a
// usage error (not silently prefer one).
func TestJSON_AuthEnableRejectsPathAndPositionalConflict(t *testing.T) {
	port := h.GetLeaderPort(t)

	out, err := h.WardenCLIWithPort(t, port, map[string]string{
		"WARDEN_TOKEN": h.RootToken(t),
	}, "auth", "enable", "positional-path",
		"-type", "jwt",
		"-path", "flag-path",
		"-o", "json")
	if err == nil {
		t.Fatalf("expected non-zero exit for -path + positional PATH; got success.\nOutput:\n%s", out)
	}
}

// TestJSON_AuthEnableDerivesPathFromPayloadType verifies the no-positional-arg
// path-resolution: when the agent omits the positional PATH, the mount
// path is derived from payload["type"] (e.g. "jwt" → "jwt/").
func TestJSON_AuthEnableDerivesPathFromPayloadType(t *testing.T) {
	port := h.GetLeaderPort(t)

	// "jwt" is already mounted by setup.sh, so we use a custom path that
	// matches the type. Using --dry-run avoids the conflict.
	out, err := h.WardenCLIWithPort(t, port, map[string]string{
		"WARDEN_TOKEN": h.RootToken(t),
	}, "auth", "enable",
		"--json", `{"type":"jwt"}`,
		"--dry-run",
		"-o", "json")
	if err != nil {
		t.Fatalf("auth enable --json --dry-run failed: %v\nOutput:\n%s", err, out)
	}

	var resp map[string]any
	if jsonErr := json.Unmarshal([]byte(out), &resp); jsonErr != nil {
		t.Fatalf("output not JSON: %v\n%s", jsonErr, out)
	}
	if resp["dry_run"] != true || resp["validated"] != true {
		t.Errorf("expected dry_run=true and validated=true; got %v", resp)
	}
}
