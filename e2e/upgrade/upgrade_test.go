//go:build e2e

// Package upgrade drives a cluster holding what an earlier release left in
// storage: auth roles, a provider config naming user_auth_role, a service
// token in the old value format. None of these can be written through today's
// API, so the test writes them into storage the way the earlier release did
// (helpers.ClusterStorage), restarts every node, and checks what this release
// makes of them.
package upgrade

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	h "github.com/stephnangue/warden/e2e/helpers"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
)

const (
	agentMount   = "auth/e2e-upgrade-jwt/"
	userMount    = "auth/e2e-upgrade-user/"
	provider     = "e2e-upgrade-vault"
	userProvider = "e2e-upgrade-vault-ul"
	policy       = "e2e-upgrade-access"
	agentRole    = "e2e-upgrade-agent"

	// The auth roles the earlier release stored on agentMount.
	legacyReader   = "legacy-reader"
	legacyDeployer = "legacy-deployer"

	secretPath = "v1/secret/data/e2e/app-config"
)

// legacyRole is an auth role as the earlier release stored it under the
// mount's role/ prefix.
func legacyRole(name string) map[string]any {
	return map[string]any{
		"name":            name,
		"bound_audiences": []string{h.HydraAudience},
		"bound_subject":   "e2e-agent",
		"token_policies":  []string{policy},
		"token_ttl":       "1h",
		"user_claim":      "sub",
		"cred_spec_name":  "vault-token-reader",
		"provider_path":   provider + "/",
	}
}

// legacyRoot is a root token as the earlier release stored it: an old type
// name, a cws. value, and an ID under the old wtkn_ prefix.
type legacyRoot struct {
	value, id, accessor string
}

func newLegacyRoot() legacyRoot {
	value := "cws." + strings.Repeat("e2eLegacyRoot", 5)[:64]
	sum := sha256.Sum256([]byte(value))
	return legacyRoot{
		value:    value,
		id:       "wtkn_" + hex.EncodeToString(sum[:])[:32],
		accessor: "e2e-legacy-root-accessor",
	}
}

func (r legacyRoot) seed(t *testing.T, s *h.ClusterStorage) {
	t.Helper()
	s.PutJSON(t, "core/token/id/"+r.id, &logical.TokenEntry{
		ID:            r.id,
		Accessor:      r.accessor,
		Type:          "warden_token",
		NamespaceID:   namespace.RootNamespaceID,
		NamespacePath: "",
		CreatedAt:     time.Now().Add(-24 * time.Hour),
		PrincipalID:   namespace.RootNamespaceUUID,
		Policies:      []string{"root"},
		Data:          map[string]string{"token": r.value},
	})
	s.Put(t, "core/token/accessor/"+r.accessor, []byte(r.id))
}

func (r legacyRoot) remove(t *testing.T, s *h.ClusterStorage) {
	t.Helper()
	s.Delete(t, "core/token/id/"+r.id)
	s.Delete(t, "core/token/accessor/"+r.accessor)
}

// restartCluster stops every node and starts them again, as an upgrade does,
// and returns the new active node's port and the offset in its log at which
// this start began.
func restartCluster(t *testing.T) (int, int) {
	t.Helper()
	offsets := map[int]int{}
	for n := 1; n <= 3; n++ {
		offsets[n] = h.NodeLogSize(t, n)
		h.KillNode(t, n, "TERM")
	}
	time.Sleep(5 * time.Second)
	for n := 1; n <= 3; n++ {
		h.RestartNode(t, n)
		time.Sleep(2 * time.Second)
	}
	h.WaitForCluster(t, 30, 2*time.Second)
	leader := h.GetLeaderPort(t)
	return leader, offsets[h.NodeNumberForPort(leader)]
}

// logLine returns the first line of lines that contains every one of parts.
func logLine(lines []string, parts ...string) string {
	for _, l := range lines {
		ok := true
		for _, p := range parts {
			ok = ok && strings.Contains(l, p)
		}
		if ok {
			return l
		}
	}
	return ""
}

func warningsOf(t *testing.T, body []byte) []string {
	t.Helper()
	var out struct {
		Warnings []string `json:"warnings"`
		Data     struct {
			Warnings []string `json:"warnings"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	return append(out.Warnings, out.Data.Warnings...)
}

func containsWarning(warnings []string, part string) bool {
	for _, w := range warnings {
		if strings.Contains(w, part) {
			return true
		}
	}
	return false
}

// setupMounts builds what the earlier release's operator had: an agent JWT
// mount, a human user mount, a provider for each leg shape, and a policy.
func setupMounts(t *testing.T, port int) {
	t.Helper()
	for _, m := range []string{agentMount, userMount} {
		sys := "sys/" + strings.TrimSuffix(m, "/")
		h.APIRequest(t, "DELETE", sys, port, "")
		h.MustNS(t, port, "", "POST", sys, `{"type":"jwt"}`)
		t.Cleanup(func() { h.APIRequest(t, "DELETE", sys, port, "") })
	}
	kinds := map[string]string{agentMount: "agent", userMount: "human"}
	for m, kind := range kinds {
		h.MustNS(t, port, "", "PUT", strings.TrimSuffix(m, "/")+"/config", fmt.Sprintf(
			`{"mode":"oidc","oidc_discovery_url":%q,"bound_issuer":%q,"bound_audiences":[%q],"user_claim":"sub","entity_kind":%q}`,
			h.HydraIssuer, h.HydraIssuer, h.HydraAudience, kind))
	}

	for p, userAuth := range map[string]string{provider: "", userProvider: userMount} {
		h.APIRequest(t, "DELETE", "sys/providers/"+p, port, "")
		h.MustNS(t, port, "", "POST", "sys/providers/"+p, `{"type":"vault"}`)
		t.Cleanup(func() { h.APIRequest(t, "DELETE", "sys/providers/"+p, port, "") })
		writeProviderConfig(t, port, p, userAuth)
	}

	h.MustNS(t, port, "", "POST", "sys/policies/cbp/"+policy, fmt.Sprintf(
		`{"policy":"path \"%[1]s/role/+/gateway*\" {\n  capabilities = [\"read\"]\n}\npath \"%[1]s/gateway*\" {\n  capabilities = [\"read\"]\n}\npath \"%[2]s/role/+/gateway*\" {\n  capabilities = [\"read\"]\n}\npath \"%[2]s/gateway*\" {\n  capabilities = [\"read\"]\n}"}`,
		provider, userProvider))
	t.Cleanup(func() { h.APIRequest(t, "DELETE", "sys/policies/cbp/"+policy, port, "") })

	h.GrantRole(t, port, agentMount, agentRole,
		h.Role{Policies: []string{policy}, CredSpec: "vault-token-reader"}, nil)
	t.Cleanup(func() { h.RevokeRoleBestEffort(port, agentMount, agentRole) })
}

// writeProviderConfig writes p's whole config: the upstream, the agent mount, and
// userAuth as the user leg when set. The write names no user_auth_role, so it
// also removes one the stored config still names.
func writeProviderConfig(t *testing.T, port int, p, userAuth string) {
	t.Helper()
	cfg := map[string]any{
		"vault_address":   "http://127.0.0.1:8200",
		"tls_skip_verify": true,
		"timeout":         "30s",
		"auto_auth_path":  agentMount,
	}
	if userAuth != "" {
		cfg["user_auth_path"] = userAuth
	}
	b, _ := json.Marshal(cfg)
	h.MustNS(t, port, "", "POST", p+"/config", string(b))
}

func gateway(t *testing.T, port int, p, role string, headers map[string]string) (int, []byte) {
	t.Helper()
	return h.DoRequest(t, "GET", fmt.Sprintf("%s/v1/%s/role/%s/gateway/%s", h.NodeURL(port), p, role, secretPath), headers, "")
}

// TestUpgrade_StoredStateAfterRestart seeds what an earlier release left
// behind, restarts the whole cluster, and checks each piece:
//
//   - auth roles stored on a mount: the new active node warns once at unseal,
//     sys/auth warns on list and read, the role paths answer 410, and an old
//     role grants nothing until it is recreated as a role and a group;
//   - a provider config still naming user_auth_role: every user credential is
//     refused (403) and the config read says why, until a config write drops
//     it;
//   - a root token in the old cws. format: it survives the restart, is
//     recognised as the root token at load, and authorizes; the root token
//     this release issued at init has the wds. format and keeps working.
func TestUpgrade_StoredStateAfterRestart(t *testing.T) {
	port := h.GetLeaderPort(t)
	setupMounts(t, port)

	if root := h.RootToken(t); !strings.HasPrefix(root, "wds.") {
		t.Fatalf("the root token issued at init is not a wds. token: %.4s...", root)
	}

	storage := h.OpenClusterStorage(t)
	authUUID := storage.AuthMountUUID(t, agentMount)
	for _, name := range []string{legacyReader, legacyDeployer} {
		storage.PutJSON(t, h.AuthMountStorage(authUUID)+"role/"+name, legacyRole(name))
	}

	providerConfigKey := h.ProviderMountStorage(storage.ProviderMountUUID(t, userProvider)) + "config"
	var stored map[string]any
	if err := json.Unmarshal(storage.Get(t, providerConfigKey), &stored); err != nil {
		t.Fatalf("decode the stored provider config: %v", err)
	}
	stored["user_auth_role"] = "legacy-user"
	storage.PutJSON(t, providerConfigKey, stored)

	root := newLegacyRoot()
	root.seed(t, storage)
	t.Cleanup(func() {
		// The node that loaded the token keeps it until it seals; stepping
		// down seals the active node's token cache, and the next one loads
		// storage without it.
		root.remove(t, storage)
		h.StepDown(t, h.GetLeaderPort(t))
		h.WaitForCluster(t, 30, 2*time.Second)
	})

	port, offset := restartCluster(t)
	lines := h.NodeLogSince(t, h.NodeNumberForPort(port), offset)

	t.Run("auth roles left in storage", func(t *testing.T) {
		const warning = "auth/e2e-upgrade-jwt/: 2 auth roles are no longer used; recreate them as roles and groups"
		if logLine(lines, warning) == "" {
			t.Errorf("the active node did not warn at unseal: want a line containing %q", warning)
		}

		status, body := h.APIRequest(t, "GET", "sys/auth?warden-list=true", port, "")
		if status != 200 || !containsWarning(warningsOf(t, body), warning) {
			t.Errorf("sys/auth list: status %d, want the warning %q: %s", status, warning, body)
		}
		status, body = h.APIRequest(t, "GET", "sys/"+strings.TrimSuffix(agentMount, "/"), port, "")
		if status != 200 || !containsWarning(warningsOf(t, body), warning) {
			t.Errorf("sys/auth read: status %d, want the warning %q: %s", status, warning, body)
		}
		status, body = h.APIRequest(t, "GET", "sys/auth/jwt", port, "")
		if status != 200 || containsWarning(warningsOf(t, body), "auth roles are no longer used") {
			t.Errorf("sys/auth read of a mount holding no auth roles warns: %s", body)
		}

		for _, method := range []string{"GET", "POST"} {
			status, body := h.APIRequest(t, method, agentMount+"role/"+legacyReader, port, `{"token_policies":["x"]}`)
			if status != http.StatusGone {
				t.Errorf("%s %srole/%s: status %d, want 410: %s", method, agentMount, legacyReader, status, body)
			}
			if strings.Contains(string(body), "bound_subject") || strings.Contains(string(body), policy) {
				t.Errorf("%s %srole/%s reads the stored role back: %s", method, agentMount, legacyReader, body)
			}
		}

		// The old role, as a request selects it: nothing grants it.
		jwt := h.GetDefaultJWT(t)
		bearer := map[string]string{"Authorization": "Bearer " + jwt}
		status, body = gateway(t, port, provider, legacyReader, bearer)
		if status != http.StatusForbidden || !strings.Contains(h.ErrorText(body), `role "`+legacyReader+`" not found`) {
			t.Errorf("a request under the stored auth role: status %d, want 403 role not found: %s", status, body)
		}
		// The mount itself admits: a role granted the new way works.
		if status, body := gateway(t, port, provider, agentRole, bearer); status != 200 {
			t.Fatalf("a request under a granted role: status %d: %s", status, body)
		}

		// Recreated as a role and a group, the same name serves traffic on
		// the next request of the same credential.
		h.GrantRole(t, port, agentMount, legacyReader,
			h.Role{Policies: []string{policy}, CredSpec: "vault-token-reader", ProviderPath: provider + "/"},
			h.Rule{"sub": {"e2e-agent"}})
		t.Cleanup(func() { h.RevokeRoleBestEffort(port, agentMount, legacyReader) })
		if status, body := gateway(t, port, provider, legacyReader, bearer); status != 200 {
			t.Errorf("the recreated role: status %d: %s", status, body)
		}
	})

	t.Run("user_auth_role left in a provider config", func(t *testing.T) {
		headers := map[string]string{
			"X-Warden-Agent-Token": h.GetDefaultJWT(t),
			"Authorization":        "Bearer " + h.UserJWT(t),
		}
		status, body := gateway(t, port, userProvider, agentRole, headers)
		if status != http.StatusForbidden || !strings.Contains(h.ErrorText(body), "user_auth_role was removed") {
			t.Fatalf("a user credential under a stored user_auth_role: status %d, want 403 naming user_auth_role: %s", status, body)
		}

		status, body = h.APIRequest(t, "GET", userProvider+"/config", port, "")
		if status != 200 || !containsWarning(warningsOf(t, body), "user credentials are refused: user_auth_role was removed") {
			t.Errorf("config read: status %d, want a warning that user credentials are refused: %s", status, body)
		}

		writeProviderConfig(t, port, userProvider, userMount)
		if status, body := gateway(t, port, userProvider, agentRole, headers); status != 200 {
			t.Errorf("after a config write without user_auth_role: status %d: %s", status, body)
		}
	})

	t.Run("cws. root token", func(t *testing.T) {
		line := logLine(lines, "more than one root token in storage", root.id)
		if line == "" {
			t.Errorf("the active node did not load %s as the root token: no load warning naming it", root.id)
		}

		u := h.NodeURL(port) + "/v1/sys/auth?warden-list=true"
		for name, token := range map[string]string{"cws. root": root.value, "wds. root": h.RootToken(t)} {
			status, body := h.DoRequest(t, "GET", u, map[string]string{"X-Warden-Token": token}, "")
			if status != 200 {
				t.Errorf("%s token after the restart: status %d: %s", name, status, body)
			}
		}
		// Through a standby too, which forwards it to the active node.
		standby := h.GetStandbyPort(t)
		status, body := h.DoRequest(t, "GET", h.NodeURL(standby)+"/v1/sys/auth?warden-list=true",
			map[string]string{"X-Warden-Token": root.value}, "")
		if status != 200 {
			t.Errorf("cws. root token through a standby: status %d: %s", status, body)
		}
	})
}
