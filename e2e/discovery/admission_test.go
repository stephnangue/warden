//go:build e2e

package discovery

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// postDiscovery POSTs body, one JSON-RPC message or a batch, to the discovery
// server of namespace with bearer, as a client of the 2025-03-26 revision
// (which allows batches), and returns one decoded response per call.
func postDiscovery(t *testing.T, port int, namespace, bearer, body string) []map[string]any {
	t.Helper()
	headers := map[string]string{
		"Authorization":        "Bearer " + bearer,
		"Content-Type":         "application/json",
		"Accept":               "application/json, text/event-stream",
		"MCP-Protocol-Version": "2025-03-26",
	}
	if namespace != "" {
		headers["X-Warden-Namespace"] = namespace
	}
	status, raw := h.DoRequest(t, "POST", h.NodeURL(port)+"/v1/sys/mcp", headers, body)
	if status != 200 {
		t.Fatalf("discovery: status %d: %s", status, raw)
	}
	var out []map[string]any
	if strings.HasPrefix(strings.TrimSpace(string(raw)), "[") {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("decode %s: %v", raw, err)
		}
		return out
	}
	var one map[string]any
	if err := json.Unmarshal(raw, &one); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	return []map[string]any{one}
}

// listRoles calls list_roles in namespace with bearer.
func listRoles(t *testing.T, port int, namespace, bearer string) rolesResult {
	t.Helper()
	out := postDiscovery(t, port, namespace, bearer,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_roles","arguments":{}}}`)
	raw, err := json.Marshal(h.JSONPath(out[0], "result.structuredContent"))
	if err != nil {
		t.Fatal(err)
	}
	var roles rolesResult
	if err := json.Unmarshal(raw, &roles); err != nil || string(raw) == "null" {
		t.Fatalf("list_roles answered no structured content: %v", out[0])
	}
	return roles
}

// discoveryNamespace creates namespace ns with custom metadata and removes it
// when the test ends.
func discoveryNamespace(t *testing.T, port int, ns, metadata string) {
	t.Helper()
	h.APIRequest(t, "DELETE", "sys/namespaces/"+ns, port, "")
	body := ""
	if metadata != "" {
		body = `{"custom_metadata":` + metadata + `}`
	}
	h.MustNS(t, port, "", "POST", "sys/namespaces/"+ns, body)
	t.Cleanup(func() { h.CleanupNamespaces(t, port, ns) })
}

// discoveryMount mounts a jwt auth method at mount in ns admitting the suites'
// Hydra tokens, as entity kind.
func discoveryMount(t *testing.T, port int, ns, mount, kind string) {
	t.Helper()
	path := strings.TrimSuffix(h.AuthMountPath(mount), "/")
	h.MustNS(t, port, ns, "POST", "sys/"+path, `{"type":"jwt"}`)
	t.Cleanup(func() { h.NSRequestBestEffort(port, ns, "DELETE", "sys/"+path) })
	h.MustNS(t, port, ns, "PUT", path+"/config", fmt.Sprintf(
		`{"mode":"oidc","oidc_discovery_url":%q,"bound_issuer":%q,"bound_audiences":[%q],"user_claim":"sub","entity_kind":%q}`,
		h.HydraIssuer, h.HydraIssuer, h.HydraAudience, kind))
}

// discoveryProvider mounts a vault provider at mount in ns whose agents are
// admitted through autoAuthPath, which need not name a mount.
func discoveryProvider(t *testing.T, port int, ns, mount, autoAuthPath string) {
	t.Helper()
	h.MustNS(t, port, ns, "POST", "sys/providers/"+mount, `{"type":"vault"}`)
	t.Cleanup(func() { h.NSRequestBestEffort(port, ns, "DELETE", "sys/providers/"+mount) })
	h.MustNS(t, port, ns, "POST", mount+"/config", fmt.Sprintf(
		`{"vault_address":"http://127.0.0.1:8200","tls_skip_verify":true,"auto_auth_path":%q}`, autoAuthPath))
}

// TestDiscovery_BatchSharesOneAdmissionPerTarget sends list_roles, two
// skills/list, skills/get, resources/read and read_skill in one JSON-RPC batch
// with a service account token, in a namespace whose only target is a
// kubernetes mount. Every call is answered, and the whole batch costs one
// TokenReview: the calls of one request share one admission per target.
func TestDiscovery_BatchSharesOneAdmissionPerTarget(t *testing.T) {
	port := h.GetLeaderPort(t)
	const (
		ns    = "e2e-disc-batch"
		mount = "auth/k8s/"
		role  = "k8s-reader"
	)
	discoveryNamespace(t, port, ns, "")
	reviewer := h.StartTokenReviewer(t)
	h.EnableKubernetesAuth(t, port, ns, mount, reviewer, map[string]any{"bound_audiences": []string{h.HydraAudience}})
	discoveryProvider(t, port, ns, "vault", mount)
	h.WriteRoleInNS(t, port, ns, role, h.Role{Policies: []string{"default"}, ProviderPath: "vault"})
	t.Cleanup(func() { h.NSRequestBestEffort(port, ns, "DELETE", "sys/roles/"+role) })
	h.WriteGroupInNS(t, port, ns, role, h.Group{
		Roles: []string{role},
		Rules: []map[string][]string{{"mount": {mount}, "service_account_name": {"reader"}}},
	})

	token := reviewer.Issue(t, h.ServiceAccount{
		Namespace: "ci", Name: "reader", UID: "uid-reader", Audiences: []string{h.HydraAudience},
	}, "https://kubernetes.e2e.example", true)

	const batch = `[
		{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_roles","arguments":{}}},
		{"jsonrpc":"2.0","id":2,"method":"skills/list","params":{}},
		{"jsonrpc":"2.0","id":3,"method":"skills/list","params":{}},
		{"jsonrpc":"2.0","id":4,"method":"skills/get","params":{"uri":"skill://vault/SKILL.md"}},
		{"jsonrpc":"2.0","id":5,"method":"resources/read","params":{"uri":"skill://vault/SKILL.md"}},
		{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"read_skill","arguments":{"uri":"skill://vault/SKILL.md"}}}
	]`
	before := reviewer.Reviews()
	out := postDiscovery(t, port, ns, token, batch)
	if len(out) != 6 {
		t.Fatalf("a batch of 6 calls got %d responses: %v", len(out), out)
	}
	for _, r := range out {
		if _, ok := r["result"]; !ok {
			t.Errorf("call %v was not answered with a result: %v", r["id"], r)
		}
	}
	if got := reviewer.Reviews() - before; got != 1 {
		t.Errorf("one batch cost %d TokenReviews, want 1", got)
	}
	roles, _ := json.Marshal(h.JSONPath(out[0], "result.structuredContent.roles"))
	if !strings.Contains(string(roles), `"`+role+`"`) {
		t.Errorf("list_roles in the batch does not list %s: %s", role, roles)
	}

	// The next request discovers afresh.
	postDiscovery(t, port, ns, token, `{"jsonrpc":"2.0","id":1,"method":"skills/list","params":{}}`)
	if got := reviewer.Reviews() - before; got != 2 {
		t.Errorf("a second request brought the TokenReviews to %d, want 2", got)
	}
}

// TestDiscovery_NamespaceTargets drives list_roles in a namespace whose
// auto_auth_path is an agent jwt mount, with three providers:
//
//   - one admitting through that mount: its role is listed with its URL;
//   - one whose auto_auth_path names no auth mount: its role, granted at the
//     namespace's mount, is listed without a URL, and the warning says the
//     provider's auto_auth_path names no auth mount;
//   - one admitting through a human mount: its role, granted there, is not
//     listed, and nothing says so (discovery never admits an agent through a
//     human mount, and no warning names the role).
func TestDiscovery_NamespaceTargets(t *testing.T) {
	port := h.GetLeaderPort(t)
	const (
		ns       = "e2e-disc-targets"
		agent    = "auth/jwt/"
		human    = "auth/people/"
		missing  = "auth/missing/"
		reachOK  = "ok-reader"
		reachNo  = "unreachable-reader"
		reachHum = "human-reader"
	)
	discoveryNamespace(t, port, ns, `{"auto_auth_path":"`+agent+`"}`)
	discoveryMount(t, port, ns, agent, "agent")
	discoveryMount(t, port, ns, human, "human")
	discoveryProvider(t, port, ns, "vault-ok", agent)
	discoveryProvider(t, port, ns, "vault-missing", missing)
	discoveryProvider(t, port, ns, "vault-human", human)

	for role, grant := range map[string]struct{ provider, mount string }{
		reachOK:  {"vault-ok", agent},
		reachNo:  {"vault-missing", agent},
		reachHum: {"vault-human", human},
	} {
		h.WriteRoleInNS(t, port, ns, role, h.Role{Policies: []string{"default"}, ProviderPath: grant.provider})
		t.Cleanup(func() { h.NSRequestBestEffort(port, ns, "DELETE", "sys/roles/"+role) })
		h.WriteGroupInNS(t, port, ns, role, h.Group{
			Roles: []string{role},
			Rules: []map[string][]string{{"mount": {grant.mount}}},
		})
	}

	roles := listRoles(t, port, ns, h.GetDefaultJWT(t))
	listed := map[string]string{}
	for _, r := range roles.Roles {
		listed[r.Name] = r.URL
	}
	if url, ok := listed[reachOK]; !ok || !strings.HasSuffix(url, "/vault-ok/role/"+reachOK+"/gateway/") {
		t.Errorf("%s: listed %v with url %q, want it listed with its gateway URL", reachOK, ok, url)
	}
	if url, ok := listed[reachNo]; !ok || url != "" {
		t.Errorf("%s: listed %v with url %q, want it listed without a URL", reachNo, ok, url)
	}
	if _, ok := listed[reachHum]; ok {
		t.Errorf("%s, granted only at a human mount, is listed", reachHum)
	}

	want := fmt.Sprintf(`role %q: provider "vault-missing/": auto_auth_path %q names no auth mount`, reachNo, missing)
	if len(roles.Warnings) != 1 || roles.Warnings[0] != want {
		t.Errorf("warnings = %q, want exactly %q", roles.Warnings, want)
	}
	for _, w := range roles.Warnings {
		if strings.Contains(w, reachHum) || strings.Contains(w, "vault-human") || strings.Contains(w, human) {
			t.Errorf("a warning names the role granted at the human mount: %s", w)
		}
	}
}
