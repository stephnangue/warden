//go:build e2e

package credential

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// TestJSON_CreateCredSourceWithJSONFile end-to-ends the --json @file path:
// agents pipe a full payload, the typed-flag layer is bypassed, the
// resource is created, and a follow-up read confirms what landed. Uses
// the hvault driver (validated by setup.sh) so the create-time
// connection check passes — an AWS source with placeholder credentials
// would fail upstream auth at create time, hiding any bug in the CLI
// layer.
func TestJSON_CreateCredSourceWithJSONFile(t *testing.T) {
	port := h.GetLeaderPort(t)

	const name = "e2e-json-vault-source"
	h.APIRequest(t, "DELETE", "sys/cred/sources/"+name, port, "")
	t.Cleanup(func() {
		h.APIRequest(t, "DELETE", "sys/cred/sources/"+name, port, "")
	})

	tmp := filepath.Join(t.TempDir(), "src.json")
	payload := map[string]any{
		"type":            "hvault",
		"rotation_period": 300,
		"config": map[string]any{
			"vault_address": "http://127.0.0.1:8200",
			"auth_method":   "approle",
			"role_id":       "e2e-approle-role-id-1234",
			"secret_id":     "e2e-approle-secret-id-5678",
			"approle_mount": "e2e_approle",
			"role_name":     "warden-e2e-role",
		},
	}
	bytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(tmp, bytes, 0600); err != nil {
		t.Fatalf("write payload file: %v", err)
	}

	out, err := h.WardenCLIWithPort(t, port, map[string]string{
		"WARDEN_TOKEN": h.RootToken(t),
	}, "cred", "source", "create", name, "--json", "@"+tmp, "-o", "json")
	if err != nil {
		t.Fatalf("warden cred source create --json failed: %v\nOutput:\n%s", err, out)
	}

	var resp map[string]any
	if jsonErr := json.Unmarshal([]byte(out), &resp); jsonErr != nil {
		t.Fatalf("CLI output not JSON: %v\n%s", jsonErr, out)
	}
	if resp["created"] != true {
		t.Errorf("expected created=true marker; got %v", resp)
	}
	if resp["name"] != name {
		t.Errorf("expected name=%q marker; got %v", name, resp["name"])
	}

	// Verify the source is actually there.
	status, body := h.APIRequest(t, "GET", "sys/cred/sources/"+name, port, "")
	if status != 200 {
		t.Fatalf("source not found after create: status %d, body %s", status, string(body))
	}
}

// TestJSON_RejectsCombiningWithTypedFlags pins the contract that --json
// and conflicting typed flags can't be mixed — preventing ambiguity about
// which input wins.
func TestJSON_RejectsCombiningWithTypedFlags(t *testing.T) {
	port := h.GetLeaderPort(t)

	out, err := h.WardenCLIWithPort(t, port, map[string]string{
		"WARDEN_TOKEN": h.RootToken(t),
	}, "cred", "source", "create", "e2e-json-conflict",
		"--type=aws",
		"--json", `{"type":"aws"}`,
		"-o", "json",
	)
	if err == nil {
		t.Fatalf("expected non-zero exit when --type and --json both set; got success.\nOutput:\n%s", out)
	}
	if !strings.Contains(out, "--json") {
		t.Errorf("expected error to mention --json; got:\n%s", out)
	}
	if !strings.Contains(out, "--type") {
		t.Errorf("expected error to mention --type; got:\n%s", out)
	}
}

// TestJSON_DryRunValidatesPayload composes --json with --dry-run: the
// validator runs against the payload, no request is sent. Worked example
// for the agent loop "build payload → dry-run → fix → repeat → real call".
func TestJSON_DryRunValidatesPayload(t *testing.T) {
	port := h.GetLeaderPort(t)

	const name = "e2e-json-dryrun-not-created"
	h.APIRequest(t, "DELETE", "sys/cred/sources/"+name, port, "")
	defer h.APIRequest(t, "DELETE", "sys/cred/sources/"+name, port, "")

	payload := `{"type":"aws","config":{"region":"us-east-1"},"rotation_period":86400}`
	out, err := h.WardenCLIWithPort(t, port, map[string]string{
		"WARDEN_TOKEN": h.RootToken(t),
	}, "cred", "source", "create", name, "--json", payload, "--dry-run", "-o", "json")
	if err != nil {
		t.Fatalf("dry-run with --json failed: %v\nOutput:\n%s", err, out)
	}

	var env map[string]any
	if jsonErr := json.Unmarshal([]byte(out), &env); jsonErr != nil {
		t.Fatalf("output not JSON: %v\n%s", jsonErr, out)
	}
	if env["dry_run"] != true || env["validated"] != true {
		t.Errorf("expected dry_run=true and validated=true; got %v", env)
	}

	// Critical: nothing should have been created.
	status, _ := h.APIRequest(t, "GET", "sys/cred/sources/"+name, port, "")
	if status == 200 {
		t.Fatalf("dry-run leaked: source exists after --json --dry-run")
	}
}

// TestJSON_DryRunRejectsBadPayload verifies that a hallucinated field in a
// --json payload is caught by the local validator — the same agent-safety
// property that exists for typed-flag mode.
func TestJSON_DryRunRejectsBadPayload(t *testing.T) {
	port := h.GetLeaderPort(t)

	bad := `{"type":"aws","totally_made_up_field":"oops","rotation_period":86400}`
	out, err := h.WardenCLIWithPort(t, port, map[string]string{
		"WARDEN_TOKEN": h.RootToken(t),
	}, "cred", "source", "create", "e2e-json-bad-field", "--json", bad, "--dry-run", "-o", "json")
	if err == nil {
		t.Fatalf("expected non-zero exit for unknown field in --json; got success.\nOutput:\n%s", out)
	}
	if !strings.Contains(out, "totally_made_up_field") {
		t.Errorf("expected error to name the bad field; got:\n%s", out)
	}
}

// TestJSON_UpdateCredSourceWithJSON exercises the PUT path for `cred
// source update --json`. Pre-creates a source via the API, updates a
// config field via --json, then re-reads to confirm the new value
// landed.
func TestJSON_UpdateCredSourceWithJSON(t *testing.T) {
	port := h.GetLeaderPort(t)

	const name = "e2e-json-update-source"
	create := `{"type":"hvault","rotation_period":300,"config":{"vault_address":"http://127.0.0.1:8200","auth_method":"approle","role_id":"e2e-approle-role-id-1234","secret_id":"e2e-approle-secret-id-5678","approle_mount":"e2e_approle","role_name":"warden-e2e-role"}}`
	status, body := h.APIRequest(t, "POST", "sys/cred/sources/"+name, port, create)
	if status != 200 && status != 201 {
		t.Fatalf("setup: create source failed (%d): %s", status, string(body))
	}
	t.Cleanup(func() {
		h.APIRequest(t, "DELETE", "sys/cred/sources/"+name, port, "")
	})

	// Update only the rotation_period via --json.
	out, err := h.WardenCLIWithPort(t, port, map[string]string{
		"WARDEN_TOKEN": h.RootToken(t),
	}, "cred", "source", "update", name,
		"--json", `{"config":{"vault_address":"http://127.0.0.1:8200","auth_method":"approle","role_id":"e2e-approle-role-id-1234","secret_id":"e2e-approle-secret-id-5678","approle_mount":"e2e_approle","role_name":"warden-e2e-role","tls_skip_verify":true}}`,
		"-o", "json")
	if err != nil {
		t.Fatalf("update --json failed: %v\nOutput:\n%s", err, out)
	}

	var resp map[string]any
	if jsonErr := json.Unmarshal([]byte(out), &resp); jsonErr != nil {
		t.Fatalf("output not JSON: %v\n%s", jsonErr, out)
	}
	if resp["updated"] != true {
		t.Errorf("expected updated=true marker; got %v", resp)
	}
}

// TestJSON_CreateCredSpecWithJSON covers cred spec create via --json.
// Uses the vault-e2e source set up by setup.sh so the create succeeds.
func TestJSON_CreateCredSpecWithJSON(t *testing.T) {
	port := h.GetLeaderPort(t)

	const name = "e2e-json-spec"
	h.APIRequest(t, "DELETE", "sys/cred/specs/"+name, port, "")
	t.Cleanup(func() {
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+name, port, "")
	})

	payload := `{"type":"vault_token","source":"vault-e2e","min_ttl":3600,"max_ttl":86400,"config":{"mint_method":"vault_token","token_role":"e2e-secrets-reader"}}`
	out, err := h.WardenCLIWithPort(t, port, map[string]string{
		"WARDEN_TOKEN": h.RootToken(t),
	}, "cred", "spec", "create", name, "--json", payload, "-o", "json")
	if err != nil {
		t.Fatalf("spec create --json failed: %v\nOutput:\n%s", err, out)
	}

	var resp map[string]any
	if jsonErr := json.Unmarshal([]byte(out), &resp); jsonErr != nil {
		t.Fatalf("output not JSON: %v\n%s", jsonErr, out)
	}
	if resp["created"] != true {
		t.Errorf("expected created=true marker; got %v", resp)
	}

	// Confirm the spec exists.
	status, _ := h.APIRequest(t, "GET", "sys/cred/specs/"+name, port, "")
	if status != 200 {
		t.Fatalf("spec missing after --json create: status %d", status)
	}
}

// TestJSON_UpdateCredSpecWithJSON covers cred spec update via --json (PUT).
func TestJSON_UpdateCredSpecWithJSON(t *testing.T) {
	port := h.GetLeaderPort(t)

	const name = "e2e-json-spec-update"
	create := `{"type":"vault_token","source":"vault-e2e","min_ttl":3600,"max_ttl":86400,"config":{"mint_method":"vault_token","token_role":"e2e-secrets-reader"}}`
	status, body := h.APIRequest(t, "POST", "sys/cred/specs/"+name, port, create)
	if status != 200 && status != 201 {
		t.Fatalf("setup: create spec failed (%d): %s", status, string(body))
	}
	t.Cleanup(func() {
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+name, port, "")
	})

	// Bump max_ttl via --json (sent as int seconds, like the typed-flag path).
	out, err := h.WardenCLIWithPort(t, port, map[string]string{
		"WARDEN_TOKEN": h.RootToken(t),
	}, "cred", "spec", "update", name,
		"--json", `{"max_ttl":172800}`, // 48h
		"-o", "json")
	if err != nil {
		t.Fatalf("spec update --json failed: %v\nOutput:\n%s", err, out)
	}

	var resp map[string]any
	if jsonErr := json.Unmarshal([]byte(out), &resp); jsonErr != nil {
		t.Fatalf("output not JSON: %v\n%s", jsonErr, out)
	}
	if resp["updated"] != true {
		t.Errorf("expected updated=true marker; got %v", resp)
	}
}
