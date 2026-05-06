//go:build e2e

package namespace

import (
	"encoding/json"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// TestJSON_NamespaceCreateWithJSON exercises `warden namespace create --json`
// end-to-end and verifies the namespace was created via a follow-up read.
// Uses h.CleanupNamespaces (which inserts a 1-second settle wait after
// each delete) — back-to-back namespace mutations without that settle
// can confuse the cluster's leader state in test runs.
func TestJSON_NamespaceCreateWithJSON(t *testing.T) {
	port := h.GetLeaderPort(t)

	const path = "e2e-json-ns"
	h.CleanupNamespaces(t, port, path)
	t.Cleanup(func() {
		h.CleanupNamespaces(t, port, path)
	})

	out, err := h.WardenCLIWithPort(t, port, map[string]string{
		"WARDEN_TOKEN": h.RootToken(t),
	}, "namespace", "create", path,
		"--json", `{"custom_metadata":{"environment":"e2e","team":"agents"}}`,
		"-o", "json")
	if err != nil {
		t.Fatalf("namespace create --json failed: %v\nOutput:\n%s", err, out)
	}

	var resp map[string]any
	if jsonErr := json.Unmarshal([]byte(out), &resp); jsonErr != nil {
		t.Fatalf("output not JSON: %v\n%s", jsonErr, out)
	}
	if resp["created"] != true {
		t.Errorf("expected created=true marker; got %v", resp)
	}

	// Confirm.
	status, _ := h.APIRequest(t, "GET", "sys/namespaces/"+path, port, "")
	if status != 200 {
		t.Fatalf("namespace missing after --json create: status %d", status)
	}
}

// TestJSON_NamespaceUpdateWithJSON exercises the PUT/update path. Pre-creates
// a namespace via the API, updates metadata via --json, confirms the
// update landed.
func TestJSON_NamespaceUpdateWithJSON(t *testing.T) {
	port := h.GetLeaderPort(t)

	const path = "e2e-json-ns-update"
	h.CleanupNamespaces(t, port, path)
	status, body := h.APIRequest(t, "POST", "sys/namespaces/"+path, port,
		`{"custom_metadata":{"original":"yes"}}`)
	if status != 200 && status != 201 {
		t.Fatalf("setup: create namespace failed (%d): %s", status, string(body))
	}
	t.Cleanup(func() {
		h.CleanupNamespaces(t, port, path)
	})

	out, err := h.WardenCLIWithPort(t, port, map[string]string{
		"WARDEN_TOKEN": h.RootToken(t),
	}, "namespace", "update", path,
		"--json", `{"custom_metadata":{"environment":"updated","team":"agents"}}`,
		"-o", "json")
	if err != nil {
		t.Fatalf("namespace update --json failed: %v\nOutput:\n%s", err, out)
	}

	var resp map[string]any
	if jsonErr := json.Unmarshal([]byte(out), &resp); jsonErr != nil {
		t.Fatalf("output not JSON: %v\n%s", jsonErr, out)
	}
	if resp["updated"] != true {
		t.Errorf("expected updated=true marker; got %v", resp)
	}
}
