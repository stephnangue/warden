//go:build e2e

package auth

import (
	"net/http"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// TestAutoAuthPathValidation verifies that setting auto_auth_path on a provider
// requires the target auth backend to exist and be a valid auth backend.
func TestAutoAuthPathValidation(t *testing.T) {
	port := h.GetLeaderPort(t)

	// Restore vault provider to its original auto_auth_path after the test.
	defer h.APIRequest(t, "PUT", "vault/config", port, `{"auto_auth_path":"auth/jwt/"}`)

	// Setting auto_auth_path to a path with no backend mounted must fail.
	status, body := h.APIRequest(t, "PUT", "vault/config", port,
		`{"auto_auth_path":"auth/nonexistent/"}`)
	if status != http.StatusBadRequest {
		t.Fatalf("expected 400 for non-existent auth path, got %d: %s", status, body)
	}

	// Setting auto_auth_path to a valid auth backend must succeed.
	status, body = h.APIRequest(t, "PUT", "vault/config", port,
		`{"auto_auth_path":"auth/jwt/"}`)
	if status != http.StatusOK {
		t.Fatalf("expected 200 for valid auth path, got %d: %s", status, body)
	}
}
