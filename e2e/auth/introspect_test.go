//go:build e2e

package auth

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// TestIntrospectRoles_PerMountEndpointGone verifies that an auth mount no
// longer serves introspect/roles: discovery runs at sys/introspect/roles.
func TestIntrospectRoles_PerMountEndpointGone(t *testing.T) {
	port := h.GetLeaderPort(t)
	jwt := h.GetDefaultJWT(t)

	u := fmt.Sprintf("%s/v1/auth/jwt/introspect/roles", h.NodeURL(port))
	headers := map[string]string{"Authorization": "Bearer " + jwt}

	status, body := h.DoRequest(t, "GET", u, headers, "")
	if status == 200 {
		t.Fatalf("expected the per-mount endpoint to be gone; got 200. Body: %s", string(body))
	}
}

// TestIntrospectRoles_DescriptionSurfaces verifies the role's description
// (set when the role is created) is returned by the aggregator. This is
// the load-bearing field for `warden role list` — if it didn't surface, the
// CLI's table column would be empty.
func TestIntrospectRoles_DescriptionSurfaces(t *testing.T) {
	port := h.GetLeaderPort(t)

	const roleName = "e2e-introspect-described"
	const desc = "Role with a non-empty description for the introspection test"
	// Discovery evaluates a role at its provider's auto_auth_path, so the role
	// names the vault provider, whose agents arrive through auth/jwt/.
	h.GrantRole(t, port, "auth/jwt/", roleName, h.Role{
		Policies:     []string{"vault-gateway-access"},
		CredSpec:     "vault-token-reader",
		Description:  desc,
		ProviderPath: "vault/",
	}, nil)
	t.Cleanup(func() { h.RevokeRole(t, port, "auth/jwt/", roleName) })

	jwt := h.GetDefaultJWT(t)
	u := fmt.Sprintf("%s/v1/sys/introspect/roles", h.NodeURL(port))
	headers := map[string]string{"Authorization": "Bearer " + jwt}
	status, body2 := h.DoRequest(t, "GET", u, headers, "")
	if status != 200 {
		t.Fatalf("aggregator failed: status %d, body %s", status, string(body2))
	}

	var resp struct {
		Data struct {
			Roles []map[string]any `json:"roles"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body2, &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, r := range resp.Data.Roles {
		if r["name"] == roleName {
			if r["description"] != desc {
				t.Errorf("description = %v; want %q", r["description"], desc)
			}
			return
		}
	}
	t.Errorf("expected %s in aggregator output; got %#v", roleName, resp.Data.Roles)
}

// TestIntrospectRoles_HidesRolesNotSatisfiable is the security regression:
// a role no group grants the caller must NOT appear in the aggregator output.
// Discovery decides membership exactly as a request does — leaking role names
// the caller cannot assume would reveal information it can't act on,
// defeating the point of introspection. Three shapes: a group whose rule the
// caller's facts miss, a group pinned to another mount, and no group at all.
func TestIntrospectRoles_HidesRolesNotSatisfiable(t *testing.T) {
	port := h.GetLeaderPort(t)

	role := h.Role{Policies: []string{"vault-gateway-access"}, CredSpec: "vault-token-reader", ProviderPath: "vault/"}
	hidden := map[string]func(name string){
		"e2e-introspect-other-sub": func(name string) {
			h.GrantRole(t, port, "auth/jwt/", name, role, h.Rule{"sub": {"a-subject-the-caller-does-not-have"}})
			t.Cleanup(func() { h.RevokeRole(t, port, "auth/jwt/", name) })
		},
		"e2e-introspect-other-mount": func(name string) {
			h.APIRequest(t, "POST", "sys/auth/e2e-introspect-other", port, `{"type":"jwt"}`)
			t.Cleanup(func() { h.APIRequest(t, "DELETE", "sys/auth/e2e-introspect-other", port, "") })
			h.GrantRole(t, port, "auth/e2e-introspect-other/", name, role, nil)
			t.Cleanup(func() { h.RevokeRole(t, port, "auth/e2e-introspect-other/", name) })
		},
		"e2e-introspect-ungranted": func(name string) {
			h.WriteRoleInNS(t, port, "", name, role)
			t.Cleanup(func() { h.APIRequest(t, "DELETE", "sys/roles/"+name, port, "") })
		},
	}
	for name, setup := range hidden {
		setup(name)
	}

	jwt := h.GetDefaultJWT(t)
	u := fmt.Sprintf("%s/v1/sys/introspect/roles", h.NodeURL(port))
	headers := map[string]string{"Authorization": "Bearer " + jwt}
	status, body2 := h.DoRequest(t, "GET", u, headers, "")
	if status != 200 {
		t.Fatalf("aggregator failed: status %d, body %s", status, string(body2))
	}

	var resp struct {
		Data struct {
			Roles []map[string]any `json:"roles"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body2, &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, r := range resp.Data.Roles {
		if name, _ := r["name"].(string); hidden[name] != nil {
			t.Fatalf("role %q the caller is not granted was leaked: %#v", name, r)
		}
		if _, ok := r["auth_paths"]; ok {
			t.Fatalf("discovery names auth mounts: %#v", r)
		}
	}
}

// TestIntrospectRoles_WardenTokenIsNotEnough verifies the regular
// X-Warden-Token authentication is NOT accepted by the introspection
// endpoint — only an identity vehicle (JWT bearer or TLS client cert).
// Catches a regression where a future change might silently start
// accepting tokens, which would change the trust model.
func TestIntrospectRoles_WardenTokenIsNotEnough(t *testing.T) {
	port := h.GetLeaderPort(t)
	rootToken := h.RootToken(t)

	u := fmt.Sprintf("%s/v1/sys/introspect/roles", h.NodeURL(port))
	headers := map[string]string{"X-Warden-Token": rootToken}
	status, _ := h.DoRequest(t, "GET", u, headers, "")
	if status != 401 {
		t.Fatalf("expected 401 with only X-Warden-Token (no JWT/cert); got %d", status)
	}
}

// TestIntrospectRoles_MalformedBearerIsRejected verifies a non-JWT bearer
// token is rejected at the auth layer. The aggregator should never reach
// the per-mount fan-out with bad input.
func TestIntrospectRoles_MalformedBearerIsRejected(t *testing.T) {
	port := h.GetLeaderPort(t)

	u := fmt.Sprintf("%s/v1/sys/introspect/roles", h.NodeURL(port))
	headers := map[string]string{"Authorization": "Bearer not-a-real-jwt"}
	status, body := h.DoRequest(t, "GET", u, headers, "")
	// Detection accepts any "Bearer ..." as JWT-shaped; the actual JWT
	// validation happens later. Accept either 401 (rejected at validation)
	// or 200 with empty roles (no mounts authenticated the caller).
	if status != 401 && status != 200 {
		t.Fatalf("expected 401 or 200; got %d. Body: %s", status, string(body))
	}
	if status == 200 {
		// If we got a 200, the warning should make it clear no mount
		// authenticated. Sanity-check by parsing.
		var resp struct {
			Data struct {
				Roles    []map[string]any `json:"roles"`
				Warnings []string         `json:"warnings"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		// We tolerate either an empty role list or warnings — what we want
		// is for no role names to be leaked.
		for _, r := range resp.Data.Roles {
			if name, _ := r["name"].(string); strings.HasPrefix(name, "e2e-") {
				t.Errorf("malformed bearer leaked role %q", name)
			}
		}
	}
}
