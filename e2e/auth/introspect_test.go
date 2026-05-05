//go:build e2e

package auth

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// TestIntrospectRoles_PerMountEndpoint covers GET
// /v1/auth/jwt/introspect/roles directly. The aggregator at sys/introspect/
// roles fans out to this same path internally, so per-mount coverage pins
// the contract the aggregator depends on.
func TestIntrospectRoles_PerMountEndpoint(t *testing.T) {
	port := h.GetLeaderPort(t)
	jwt := h.GetDefaultJWT(t)

	u := fmt.Sprintf("%s/v1/auth/jwt/introspect/roles", h.NodeURL(port))
	headers := map[string]string{"Authorization": "Bearer " + jwt}

	status, body := h.DoRequest(t, "GET", u, headers, "")
	if status != 200 {
		t.Fatalf("expected 200; got %d. Body: %s", status, string(body))
	}

	var resp struct {
		Data struct {
			Roles []map[string]any `json:"roles"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, string(body))
	}
	if len(resp.Data.Roles) == 0 {
		t.Fatalf("expected at least one role from auth/jwt/; got 0\n%s", string(body))
	}
	// Per-mount results don't carry auth_path — the aggregator adds it.
	for _, r := range resp.Data.Roles {
		if _, ok := r["auth_path"]; ok {
			t.Errorf("per-mount response leaked auth_path; got %#v", r)
		}
		if _, ok := r["name"].(string); !ok {
			t.Errorf("per-mount role missing name; got %#v", r)
		}
	}
}

// TestIntrospectRoles_DescriptionSurfaces verifies the role's description
// (set when the role is created) is returned by the aggregator. This is
// the load-bearing field for `warden roles` — if it didn't surface, the
// CLI's table column would be empty.
func TestIntrospectRoles_DescriptionSurfaces(t *testing.T) {
	port := h.GetLeaderPort(t)

	const roleName = "e2e-introspect-described"
	const desc = "Role with a non-empty description for the introspection test"
	body := fmt.Sprintf(
		`{"token_policies":["vault-gateway-access"],"cred_spec_name":"vault-token-reader","user_claim":"sub","token_ttl":300,"description":%q}`,
		desc)
	status, respBody := h.APIRequest(t, "POST", "auth/jwt/role/"+roleName, port, body)
	if status != 200 && status != 201 && status != 204 {
		t.Fatalf("create role failed: status %d, body %s", status, string(respBody))
	}
	t.Cleanup(func() {
		h.APIRequest(t, "DELETE", "auth/jwt/role/"+roleName, port, "")
	})

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
// a role whose bound_audiences does NOT match the caller's JWT must NOT
// appear in the aggregator output. The matcher used during introspection
// must match the one used during login — leaking role names callable
// neither here nor elsewhere would reveal information the caller can't act
// on, defeating the point of introspection.
func TestIntrospectRoles_HidesRolesNotSatisfiable(t *testing.T) {
	port := h.GetLeaderPort(t)

	const roleName = "e2e-introspect-bound-other"
	body := `{"token_policies":["vault-gateway-access"],"cred_spec_name":"vault-token-reader","user_claim":"sub","token_ttl":300,"bound_audiences":["audience-the-caller-does-not-have"]}`
	status, respBody := h.APIRequest(t, "POST", "auth/jwt/role/"+roleName, port, body)
	if status != 200 && status != 201 && status != 204 {
		t.Fatalf("create role failed: status %d, body %s", status, string(respBody))
	}
	t.Cleanup(func() {
		h.APIRequest(t, "DELETE", "auth/jwt/role/"+roleName, port, "")
	})

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
			t.Fatalf("role %q with mismatched bound_audiences was leaked: %#v", roleName, r)
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
