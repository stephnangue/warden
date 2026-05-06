//go:build e2e

package credential

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// TestDryRun_NoMutation_OnValidPayload verifies that --dry-run on a valid
// `cred source create` exits 0 and does NOT actually create the resource.
// This is the core agent-safety property: the flag must be local-only —
// nothing leaves the process.
func TestDryRun_NoMutation_OnValidPayload(t *testing.T) {
	leader := h.GetLeaderPort(t)
	port := leader

	const name = "e2e-dryrun-not-created"

	// Make sure the source doesn't pre-exist (clean slate).
	h.APIRequest(t, "DELETE", "sys/cred/sources/"+name, port, "")

	out, err := h.WardenCLIWithPort(t, port, map[string]string{
		"WARDEN_TOKEN": h.RootToken(t),
	},
		"cred", "source", "create", name,
		"--type", "aws",
		"--config", "access_key_id=fake",
		"--config", "secret_access_key=fake",
		"--config", "region=us-east-1",
		"--rotation-period", "24h",
		"--dry-run",
		"-o", "json",
	)
	if err != nil {
		t.Fatalf("warden cred source create --dry-run failed: %v\nOutput:\n%s", err, out)
	}

	// stdout should be a JSON envelope marking dry-run success.
	var env map[string]any
	if jsonErr := json.Unmarshal([]byte(out), &env); jsonErr != nil {
		t.Fatalf("dry-run output not JSON: %v\n%s", jsonErr, out)
	}
	if env["dry_run"] != true {
		t.Errorf("expected dry_run=true in envelope; got %v", env)
	}
	if env["validated"] != true {
		t.Errorf("expected validated=true in envelope; got %v", env)
	}

	// Critical: the source must NOT have been created.
	status, body := h.APIRequest(t, "GET", "sys/cred/sources/"+name, port, "")
	if status == 200 {
		t.Fatalf("dry-run leaked: source %q exists after dry-run call. Body: %s", name, string(body))
	}
}

// TestDryRun_RejectsUnknownField verifies the validator catches a
// hallucinated field — the canonical agent failure mode the flag exists to
// prevent. Uses generic write so we can inject a bogus key directly.
func TestDryRun_RejectsUnknownField(t *testing.T) {
	leader := h.GetLeaderPort(t)
	port := leader

	const name = "e2e-dryrun-unknown-field"

	out, err := h.WardenCLIWithPort(t, port, map[string]string{
		"WARDEN_TOKEN": h.RootToken(t),
	},
		"write", "sys/cred/sources/"+name,
		"type=aws",
		"definitelynotafield=oops",
		"rotation_period=24h",
		"--dry-run",
		"-o", "json",
	)
	if err == nil {
		t.Fatalf("expected non-zero exit for unknown field; got success. Output:\n%s", out)
	}
	// The combined output should mention the unknown field. We don't pin
	// the exit code here because WardenCLI returns the wrapped error, but
	// the central renderer's structured envelope on stderr is captured in
	// `out`.
	if !strings.Contains(out, "definitelynotafield") {
		t.Errorf("expected output to mention the unknown field; got:\n%s", out)
	}
	if !strings.Contains(out, "invalid_input") && !strings.Contains(out, "unknown field") {
		t.Errorf("expected invalid_input classification or 'unknown field' phrase; got:\n%s", out)
	}

	// Sanity: confirm no resource was created.
	status, _ := h.APIRequest(t, "GET", "sys/cred/sources/"+name, port, "")
	if status == 200 {
		t.Fatalf("a failing dry-run still leaked state for %q", name)
	}
}

// TestDryRun_RejectsMissingRequired exercises the required-field branch of
// the validator: cred source create needs `type` and `rotation_period`.
// Omitting one should cause a clean local validation failure.
func TestDryRun_RejectsMissingRequired(t *testing.T) {
	leader := h.GetLeaderPort(t)
	port := leader

	const name = "e2e-dryrun-missing-required"

	// Skip --rotation-period — server schema marks it required.
	out, err := h.WardenCLIWithPort(t, port, map[string]string{
		"WARDEN_TOKEN": h.RootToken(t),
	},
		"write", "sys/cred/sources/"+name,
		"type=aws",
		"--dry-run",
		"-o", "json",
	)
	if err == nil {
		t.Fatalf("expected non-zero exit for missing required field; got success. Output:\n%s", out)
	}
	if !strings.Contains(out, "rotation_period") || !strings.Contains(out, "missing") {
		t.Errorf("expected error mentioning required rotation_period; got:\n%s", out)
	}
}

// TestDryRun_TemplateMatchedPath proves an agent can run --dry-run against a
// concrete path (sys/cred/sources/anything) and the server's schema endpoint
// matches it to the templated /sys/cred/sources/{name} entry. Without
// template matching, this would 404 and the validator would report
// "schema not found", which agents would interpret as broken.
func TestDryRun_TemplateMatchedPath(t *testing.T) {
	leader := h.GetLeaderPort(t)
	port := leader

	out, err := h.WardenCLIWithPort(t, port, map[string]string{
		"WARDEN_TOKEN": h.RootToken(t),
	},
		"schema", fmt.Sprintf("sys/cred/sources/%s", "any-concrete-name"),
		"-o", "json",
	)
	if err != nil {
		t.Fatalf("schema lookup with concrete path should template-match; got error: %v\nOutput:\n%s", err, out)
	}
	var env map[string]any
	if jsonErr := json.Unmarshal([]byte(out), &env); jsonErr != nil {
		t.Fatalf("schema output not JSON: %v\n%s", jsonErr, out)
	}
	// Must report the templated path key, not the concrete one.
	if got, _ := env["path"].(string); !strings.Contains(got, "{") {
		t.Errorf("expected templated path key in projection; got %q", got)
	}
}
