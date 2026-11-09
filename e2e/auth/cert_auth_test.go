//go:build e2e

package auth

import (
	"strings"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// T-C10: Cert auth config read; the auth role endpoints are gone (410) and
// point at namespace roles and groups, whose CRUD replaces them.
func TestCertAuthConfigAndRoleEndpointsGone(t *testing.T) {
	port := h.GetLeaderPort(t)
	_, _ = h.SetupCertAuth(t, port)
	defer h.TeardownCertAuth(t, port)

	// Read config
	status, body := h.APIRequest(t, "GET", "auth/cert/config", port, "")
	if status != 200 {
		t.Fatalf("expected 200 for config read, got %d: %s", status, string(body))
	}

	// Every operation under auth/cert/role/ answers 410, naming where roles
	// and their grants live now.
	for _, op := range []struct{ method, path, body string }{
		{"POST", "auth/cert/role/test-crud", `{"allowed_common_names":["test-*"],"token_policies":["default"]}`},
		{"GET", "auth/cert/role/test-crud", ""},
		{"PUT", "auth/cert/role/test-crud", `{"token_ttl":1800}`},
		{"GET", "auth/cert/role/?list=true", ""},
		{"DELETE", "auth/cert/role/test-crud", ""},
	} {
		status, body := h.APIRequest(t, op.method, op.path, port, op.body)
		if status != 410 {
			t.Fatalf("%s %s: expected 410, got %d: %s", op.method, op.path, status, body)
		}
		if !strings.Contains(string(body), "sys/roles") {
			t.Fatalf("%s %s: expected the 410 to point at sys/roles, got: %s", op.method, op.path, body)
		}
	}

	// The replacement: a namespace role and a group granting it at the mount.
	h.GrantRole(t, port, "auth/cert/", "test-crud", h.Role{Policies: []string{"default"}}, h.Rule{"cn": {"test-*"}})
	defer h.RevokeRole(t, port, "auth/cert/", "test-crud")

	status, body = h.APIRequest(t, "GET", "sys/roles/test-crud", port, "")
	if status != 200 {
		t.Fatalf("expected 200 for role read, got %d: %s", status, body)
	}
	status, body = h.APIRequest(t, "GET", "sys/identity/group/"+h.GrantGroup("auth/cert/", "test-crud"), port, "")
	if status != 200 {
		t.Fatalf("expected 200 for group read, got %d: %s", status, body)
	}
	if !strings.Contains(string(body), `"auth/cert/"`) || !strings.Contains(string(body), `"test-*"`) {
		t.Fatalf("expected the group rule to pin auth/cert/ and the CN, got: %s", body)
	}
}

// TestJWTRoleEndpointsGone verifies auth/jwt/role/* answers 410 too, so a
// script still writing auth roles fails loudly instead of granting nothing.
func TestJWTRoleEndpointsGone(t *testing.T) {
	port := h.GetLeaderPort(t)
	status, body := h.APIRequest(t, "POST", "auth/jwt/role/e2e-gone", port,
		`{"token_policies":["vault-gateway-access"],"user_claim":"sub"}`)
	if status != 410 {
		t.Fatalf("expected 410 for an auth role write, got %d: %s", status, body)
	}
	status, _ = h.APIRequest(t, "GET", "auth/jwt/role/e2e-reader", port, "")
	if status != 410 {
		t.Fatalf("expected 410 for an auth role read, got %d", status)
	}
}
