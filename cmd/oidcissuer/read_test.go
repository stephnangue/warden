package oidcissuer

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
)

// captureStdout runs fn and returns everything it wrote to os.Stdout.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	fn()
	_ = w.Close()
	out, _ := io.ReadAll(r)
	return string(out)
}

// TestPrintOIDCIssuerTable checks the coherent read table: durations render as duration
// strings (not bare seconds), and nested blocks expand into dot-keyed rows (not one crammed
// comma-joined cell). Numbers arrive as json.Number, matching the API client's UseNumber decode.
func TestPrintOIDCIssuerTable(t *testing.T) {
	data := map[string]any{
		"enabled":             true,
		"ready":               true,
		"issuer_url":          "https://warden.example.com",
		"assertion_ttl":       json.Number("300"),
		"jwks_cache_ttl":      json.Number("60"),
		"retired_key_grace":   json.Number("3600"),
		"key_rotation_period": json.Number("86400"),
		"key_rotation": map[string]any{
			"running":         true,
			"last_rotated_at": "2026-08-03T20:00:11Z",
			"next_rotation":   "2026-08-04T20:00:11Z",
		},
		"publisher": map[string]any{
			"type":            "azure_blob",
			"account_name":    "wardenoidc16865",
			"container":       "jwks",
			"client_id":       "74f14cfc-860d-4c1d-87d0-48699a24f084",
			"client_secret":   "***********",
			"rotation_period": "1m",
		},
		"publisher_rotation": map[string]any{
			"running":         true,
			"last_rotated_at": "2026-08-03T20:00:11Z",
			"next_rotation":   "2026-08-03T20:01:11Z",
		},
	}

	out := captureStdout(t, func() { printOIDCIssuerTable(data) })

	// Durations render human-readably, not as bare seconds.
	for _, want := range []string{"5m0s", "1m0s", "1h0m0s", "24h0m0s"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected duration %q in output:\n%s", want, out)
		}
	}
	// Nested blocks are expanded into dot-keyed rows.
	for _, want := range []string{
		"publisher.account_name", "wardenoidc16865",
		"publisher.client_secret", "***********",
		"key_rotation.running", "key_rotation.next_rotation",
		"publisher_rotation.last_rotated_at",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
	// publisher.rotation_period is normalized to a canonical duration.
	if !strings.Contains(out, "publisher.rotation_period") {
		t.Errorf("expected publisher.rotation_period row:\n%s", out)
	}
	// The old crammed comma-joined nested cell must be gone.
	if strings.Contains(out, "account_name=wardenoidc16865") {
		t.Errorf("nested map should not render as a crammed key=value cell:\n%s", out)
	}
}

// TestPrintOIDCIssuerTable_Disabled checks the disabled/minimal shapes: a 0 rotation period
// reads as "disabled" and no key_rotation block is shown; a bare {enabled:false} still renders.
func TestPrintOIDCIssuerTable_Disabled(t *testing.T) {
	data := map[string]any{
		"enabled":             true,
		"ready":               true,
		"issuer_url":          "https://warden.example.com",
		"assertion_ttl":       json.Number("300"),
		"jwks_cache_ttl":      json.Number("60"),
		"retired_key_grace":   json.Number("3600"),
		"key_rotation_period": json.Number("0"),
	}
	out := captureStdout(t, func() { printOIDCIssuerTable(data) })
	if !strings.Contains(out, "disabled") {
		t.Errorf("expected key_rotation_period to read 'disabled':\n%s", out)
	}
	if strings.Contains(out, "key_rotation.") {
		t.Errorf("no key_rotation block expected when disabled:\n%s", out)
	}

	out = captureStdout(t, func() { printOIDCIssuerTable(map[string]any{"enabled": false}) })
	if !strings.Contains(out, "enabled") || !strings.Contains(out, "false") {
		t.Errorf("minimal {enabled:false} should still render:\n%s", out)
	}
}
