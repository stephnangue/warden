//go:build e2e

package roles

import (
	"strings"
	"testing"
	"time"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// TestValidUntil_GroupGrantsUntilItsEnd: a group grants nothing once its
// valid_until has passed. A group written with an end already past is stored
// with a warning and grants nothing; one ending a few seconds from now grants
// the role, and the membership the first request cached expires on the first
// request past that instant, with no new login and no group write.
func TestValidUntil_GroupGrantsUntilItsEnd(t *testing.T) {
	port := h.GetLeaderPort(t)
	const (
		mount    = "auth/e2e-roles-until-jwt/"
		provider = "e2e-roles-until-vault"
		past     = "e2e-roles-until-past"
		soon     = "e2e-roles-until-soon"
	)
	h.EnableAuth(t, port, "", mount, "jwt", h.HydraJWTConfig(nil))
	policy := h.VaultProvider(t, port, "", provider, mount)
	rule := []map[string][]string{{"mount": {mount}, "sub": {"e2e-agent"}}}
	jwt := h.GetDefaultJWT(t)

	writeRole(t, port, "", past, h.Role{Policies: []string{policy}, CredSpec: "vault-token-reader"})
	warnings := h.WriteGroupInNS(t, port, "", past, h.Group{
		Roles: []string{past}, Rules: rule,
		ValidUntil: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
	})
	if !containsAny(warnings, "valid_until") {
		t.Errorf("a group ending in the past is written without a warning: %v", warnings)
	}
	status, body := get(t, gatewayURL(port, provider, past), bearer(jwt))
	expectRefused(t, "a role whose only group has ended", status, body, 403, "not assumable")

	writeRole(t, port, "", soon, h.Role{Policies: []string{policy}, CredSpec: "vault-token-reader"})
	end := time.Now().Add(8 * time.Second).Truncate(time.Second)
	h.WriteGroupInNS(t, port, "", soon, h.Group{
		Roles: []string{soon}, Rules: rule,
		ValidUntil: end.UTC().Format(time.RFC3339),
	})
	start := time.Now()
	status, body = get(t, gatewayURL(port, provider, soon), bearer(jwt))
	expectStatus(t, "a role whose group has not ended", status, body, 200)

	time.Sleep(time.Until(end) + time.Second)
	status, body = get(t, gatewayURL(port, provider, soon), bearer(jwt))
	expectRefused(t, "the first request past the group's end", status, body, 403, "not assumable")

	// Both requests ran on one admission: the cached membership expired, the
	// admission did not.
	entries := gatewayEntries(t, port, soon, start, 2)
	if entries[0].Auth.TokenAccessor != entries[1].Auth.TokenAccessor {
		t.Errorf("the request past the end logged in again: accessors %s and %s",
			entries[0].Auth.TokenAccessor, entries[1].Auth.TokenAccessor)
	}
	if !strings.HasPrefix(entries[1].Auth.RoleDeniedReason, "not assumable") {
		t.Errorf("audit role_denied_reason = %q, want not assumable", entries[1].Auth.RoleDeniedReason)
	}
}
