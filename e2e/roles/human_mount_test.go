//go:build e2e

package roles

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// TestHumanMount_RefusedOnTheAgentLeg points an MCP gateway at a human jwt
// mount for its agents, with a role granted at that mount. The agent leg never
// admits through a human mount: the request is refused before any policy runs,
// nothing reaches the upstream, and the provider's config read warns. Flipping
// the mount to agent admits the same JWT on the next request.
func TestHumanMount_RefusedOnTheAgentLeg(t *testing.T) {
	port := h.GetLeaderPort(t)
	const (
		mount = "auth/e2e-roles-human/"
		mcp   = "e2e-roles-mcp"
		role  = "e2e-roles-human-agent"
	)
	enableAuth(t, port, "", mount, "jwt", hydraConfig(map[string]any{"entity_kind": "human"}))

	upstream := h.StartRecordingUpstream(t)
	t.Cleanup(upstream.Close)
	upstream.SetHandler(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}`))
	})
	policies := mcpProvider(t, port, mcp, upstream.URL, mount)
	writeRole(t, port, "", role, h.Role{Policies: policies, CredSpec: mcp + "-cred"})
	h.WriteGroupInNS(t, port, "", role, h.Group{Roles: []string{role}, Rules: []map[string][]string{{"mount": {mount}}}})

	jwt := h.GetDefaultJWT(t)
	viaMCP := func() (int, []byte) {
		t.Helper()
		headers := bearer(jwt)
		headers["Content-Type"] = "application/json"
		return h.DoRequest(t, "POST", fmt.Sprintf("%s/v1/%s/role/%s/gateway", h.NodeURL(port), mcp, role), headers,
			`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo"}}`)
	}

	status, body := viaMCP()
	expectRefused(t, "MCP gateway, agent admitted through a human mount", status, body, 401,
		"agent leg cannot admit through a human mount")
	if n := len(upstream.Requests()); n != 0 {
		t.Fatalf("a refused agent reached the MCP upstream %d times", n)
	}
	status, body = h.APIRequest(t, "GET", mcp+"/config", port, "")
	if status != 200 || !strings.Contains(string(body), "names a human auth mount") {
		t.Errorf("config read: status %d, want a warning that auto_auth_path names a human mount: %s", status, body)
	}

	h.MustNS(t, port, "", "PUT", strings.TrimSuffix(mount, "/")+"/config", `{"entity_kind":"agent"}`)

	status, body = viaMCP()
	expectStatus(t, "MCP gateway once the mount admits agents", status, body, 200)
	if n := len(upstream.Requests()); n != 1 {
		t.Errorf("the MCP upstream got %d requests, want 1", n)
	}
}

// mcpProvider mounts an MCP gateway at mount in front of upstreamURL, its
// agents admitted through authMount, with an api_key credential and an
// unrestricted tool contract, and returns the policies a role needs to use it.
func mcpProvider(t *testing.T, port int, mount, upstreamURL, authMount string) []string {
	t.Helper()
	h.NSRequestBestEffort(port, "", "DELETE", "sys/providers/"+mount)
	h.MustNS(t, port, "", "POST", "sys/providers/"+mount, `{"type":"mcp"}`)
	t.Cleanup(func() { h.NSRequestBestEffort(port, "", "DELETE", "sys/providers/"+mount) })
	h.MustNS(t, port, "", "POST", mount+"/config", mustJSON(t, map[string]any{
		"mcp_url":         upstreamURL,
		"tls_skip_verify": true,
		"auto_auth_path":  authMount,
	}))

	source, spec := mount+"-src", mount+"-cred"
	h.NSRequestBestEffort(port, "", "DELETE", "sys/cred/specs/"+spec)
	h.NSRequestBestEffort(port, "", "DELETE", "sys/cred/sources/"+source)
	h.MustNS(t, port, "", "POST", "sys/cred/sources/"+source, `{"type":"local"}`)
	t.Cleanup(func() { h.NSRequestBestEffort(port, "", "DELETE", "sys/cred/sources/"+source) })
	h.MustNS(t, port, "", "POST", "sys/cred/specs/"+spec, mustJSON(t, map[string]any{
		"type": "api_key", "source": source, "config": map[string]string{"api_key": "e2e-roles-not-a-real-api-key"},
	}))
	t.Cleanup(func() { h.NSRequestBestEffort(port, "", "DELETE", "sys/cred/specs/"+spec) })

	cbp, contract := mount+"-access", mount+"-mcp"
	h.MustNS(t, port, "", "POST", "sys/policies/cbp/"+cbp, mustJSON(t, map[string]any{
		"policy": fmt.Sprintf("path %q {\n  capabilities = [\"read\",\"create\",\"update\"]\n}\n", mount+"/role/+/gateway*"),
	}))
	t.Cleanup(func() { h.NSRequestBestEffort(port, "", "DELETE", "sys/policies/cbp/"+cbp) })
	h.MustNS(t, port, "", "POST", "sys/policies/mcp/"+contract, mustJSON(t, map[string]any{
		"policy": fmt.Sprintf("path %q {\n%s\n}\n", mount+"/role/+/gateway*", h.MCPUnrestricted),
	}))
	t.Cleanup(func() { h.NSRequestBestEffort(port, "", "DELETE", "sys/policies/mcp/"+contract) })
	return []string{cbp, contract}
}
