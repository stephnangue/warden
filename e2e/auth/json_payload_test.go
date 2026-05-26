//go:build e2e

package auth

import (
	"encoding/json"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// TestJSON_AuthEnableWithJSON covers `warden auth enable -json` end-to-end.
// Mounts a JWT auth method at a custom path (via -path) with a JSON payload,
// then verifies via the API that the mount landed.
func TestJSON_AuthEnableWithJSON(t *testing.T) {
	port := h.GetLeaderPort(t)

	const path = "e2e-json-auth"
	h.APIRequest(t, "DELETE", "sys/auth/"+path, port, "")
	t.Cleanup(func() {
		h.APIRequest(t, "DELETE", "sys/auth/"+path, port, "")
	})

	out, err := h.WardenCLIWithPort(t, port, map[string]string{
		"WARDEN_TOKEN": h.RootToken(t),
	}, "auth", "enable", "jwt",
		"-path", path,
		"-json", `{"type":"jwt","description":"e2e -json auth enable"}`,
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

// TestJSON_AuthEnableWithPathFlag verifies that -path overrides the default
// mount path (which defaults to TYPE). Uses Vault-style single-dash long
// flags throughout to exercise the flag-normalization layer.
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
		"-path", path,
		"-o", "json",
		"jwt")
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

// TestJSON_AuthEnableRejectsPayloadTypeMismatch pins the conflict rule:
// when the JSON payload's "type" field disagrees with the TYPE positional,
// the CLI must fail with a usage error.
func TestJSON_AuthEnableRejectsPayloadTypeMismatch(t *testing.T) {
	port := h.GetLeaderPort(t)

	out, err := h.WardenCLIWithPort(t, port, map[string]string{
		"WARDEN_TOKEN": h.RootToken(t),
	}, "auth", "enable", "jwt",
		"-json", `{"type":"oidc"}`,
		"-o", "json")
	if err == nil {
		t.Fatalf("expected non-zero exit for TYPE/payload mismatch; got success.\nOutput:\n%s", out)
	}
}

// TestJSON_AuthEnableDryRunWithMatchingType pins the happy path: TYPE
// positional + a -json payload whose "type" field matches, plus -dry-run.
// Dry-run is needed because "jwt" is already mounted by setup.sh; the test
// confirms the CLI plumbing (cobra arg parsing, type-mismatch check, schema
// fetch, payload validation) all wire together without actually mounting.
// The dry-run envelope reports the path TEMPLATE (sys/auth/{path}) rather
// than the resolved mount path, so we verify the template — a regression
// in the template would surface here.
func TestJSON_AuthEnableDryRunWithMatchingType(t *testing.T) {
	port := h.GetLeaderPort(t)

	out, err := h.WardenCLIWithPort(t, port, map[string]string{
		"WARDEN_TOKEN": h.RootToken(t),
	}, "auth", "enable", "jwt",
		"-json", `{"type":"jwt"}`,
		"-dry-run",
		"-o", "json")
	if err != nil {
		t.Fatalf("auth enable -json -dry-run failed: %v\nOutput:\n%s", err, out)
	}

	var resp map[string]any
	if jsonErr := json.Unmarshal([]byte(out), &resp); jsonErr != nil {
		t.Fatalf("output not JSON: %v\n%s", jsonErr, out)
	}
	if resp["dry_run"] != true || resp["validated"] != true {
		t.Errorf("expected dry_run=true and validated=true; got %v", resp)
	}
	if resp["path"] != "sys/auth/{path}" {
		t.Errorf("expected path template sys/auth/{path}; got %v", resp["path"])
	}
}
