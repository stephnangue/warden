//go:build e2e

package auth

import (
	"encoding/json"
	"fmt"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// TestIntrospectRoles_AggregatorReturnsCallerJWTRoles verifies that
// GET /v1/sys/introspect/roles, called with a JWT bearer, returns the union
// of roles bound to the caller's identity across the namespace's auth/jwt/
// mounts. This is the server-side surface that backs the `warden role list` CLI.
func TestIntrospectRoles_AggregatorReturnsCallerJWTRoles(t *testing.T) {
	port := h.GetLeaderPort(t)
	jwt := h.GetDefaultJWT(t)

	u := fmt.Sprintf("%s/v1/sys/introspect/roles", h.NodeURL(port))
	headers := map[string]string{"Authorization": "Bearer " + jwt}

	status, body := h.DoRequest(t, "GET", u, headers, "")
	if status != 200 {
		t.Fatalf("expected 200 with JWT bearer; got %d. Body: %s", status, string(body))
	}

	var resp struct {
		Data struct {
			Roles []map[string]any `json:"roles"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal aggregator response: %v. Body: %s", err, string(body))
	}
	if len(resp.Data.Roles) == 0 {
		t.Fatalf("expected at least one role; got 0. Body: %s", string(body))
	}
	found := false
	for _, r := range resp.Data.Roles {
		if r["name"] == "e2e-reader" {
			found = true
			// auth_path matches `warden auth list`'s convention: the
			// mount-table path relative to the auth route prefix (e.g.
			// "jwt/"), NOT the router-visible "auth/jwt/".
			if r["auth_path"] != "jwt/" {
				t.Errorf("auth_path = %v; want jwt/", r["auth_path"])
			}
		}
	}
	if !found {
		t.Errorf("expected e2e-reader in aggregator roles; got %#v", resp.Data.Roles)
	}
}

// TestIntrospectRoles_NoIdentityVehicle verifies the endpoint requires either
// a JWT bearer or a TLS client cert — a Warden token alone is not an identity.
func TestIntrospectRoles_NoIdentityVehicle(t *testing.T) {
	port := h.GetLeaderPort(t)

	u := fmt.Sprintf("%s/v1/sys/introspect/roles", h.NodeURL(port))
	status, _ := h.DoRequest(t, "GET", u, nil, "")
	if status != 401 {
		t.Fatalf("expected 401 without bearer/cert; got %d", status)
	}
}

// TestRolesCLI_JWTPromotesToBearer is the regression test for the
// cmd/helpers/client.go WARDEN_TOKEN-to-Authorization-Bearer promotion: a
// JWT-shaped WARDEN_TOKEN must reach the introspect endpoint via
// `Authorization: Bearer`, since the endpoint specifically does not look
// at X-Warden-Token. Without the promotion this would 401.
func TestRolesCLI_JWTPromotesToBearer(t *testing.T) {
	port := h.GetLeaderPort(t)
	jwt := h.GetDefaultJWT(t)

	out, err := h.WardenCLIWithPort(t, port, map[string]string{
		"WARDEN_TOKEN": jwt,
	}, "role", "list", "-o", "json")
	if err != nil {
		t.Fatalf("warden role list failed: %v\nOutput:\n%s", err, out)
	}

	var roles []map[string]any
	if err := json.Unmarshal([]byte(out), &roles); err != nil {
		t.Fatalf("warden role list -o json output is not a JSON list: %v\nOutput:\n%s", err, out)
	}
	if len(roles) == 0 {
		t.Fatalf("expected at least one role in CLI output; got 0\nOutput:\n%s", out)
	}
	found := false
	for _, r := range roles {
		if r["name"] == "e2e-reader" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected e2e-reader in CLI roles; got: %s", out)
	}
}

// TestRolesCLI_AuthPathFilter verifies the --auth-path filter narrows the
// CLI output to roles on the specified mount.
func TestRolesCLI_AuthPathFilter(t *testing.T) {
	port := h.GetLeaderPort(t)
	jwt := h.GetDefaultJWT(t)

	out, err := h.WardenCLIWithPort(t, port, map[string]string{
		"WARDEN_TOKEN": jwt,
	}, "role", "list", "-o", "json", "--auth-path", "jwt/")
	if err != nil {
		t.Fatalf("warden role list --auth-path failed: %v\nOutput:\n%s", err, out)
	}

	var roles []map[string]any
	if err := json.Unmarshal([]byte(out), &roles); err != nil {
		t.Fatalf("output not JSON: %v\n%s", err, out)
	}
	if len(roles) == 0 {
		t.Fatalf("filter excluded everything; expected at least one role")
	}
	for _, r := range roles {
		if got := fmt.Sprintf("%v", r["auth_path"]); got != "jwt/" {
			t.Errorf("filter leaked: auth_path = %q; want jwt/", got)
		}
	}
}
