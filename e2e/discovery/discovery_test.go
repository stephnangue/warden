//go:build e2e

// Package discovery exercises Warden's own MCP server — the discovery
// interface at /v1/sys/mcp (list_roles + read_skill) — end to end against the
// live cluster, following the roles.md scenario: an agent connects, lists the
// roles its identity can assume, takes a role's skill URI and URL, and reads
// that skill — the recipe that teaches it how to drive the provider through
// the gateway.
package discovery

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// jwtRoundTripper presents the agent's JWT on every request and trusts the
// self-signed e2e cert.
type jwtRoundTripper struct {
	base http.RoundTripper
	jwt  string
}

func (rt jwtRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	r.Header.Set("Authorization", "Bearer "+rt.jwt)
	return rt.base.RoundTrip(r)
}

// connectDiscovery dials the leader's /v1/sys/mcp with the default JWT and
// returns a connected MCP client session.
func connectDiscovery(t *testing.T) *mcp.ClientSession {
	t.Helper()
	port := h.GetLeaderPort(t)
	jwt := h.GetDefaultJWT(t)

	client := mcp.NewClient(&mcp.Implementation{Name: "e2e-agent", Version: "1.0.0"}, nil)
	transport := &mcp.StreamableClientTransport{
		Endpoint: h.NodeURL(port) + "/v1/sys/mcp",
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: jwtRoundTripper{
				base: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // self-signed e2e cert
				},
				jwt: jwt,
			},
		},
		DisableStandaloneSSE: true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("connect to /v1/sys/mcp: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

// decodeStructured re-decodes a tool result's structured content into dst.
func decodeStructured(t *testing.T, res *mcp.CallToolResult, dst any) {
	t.Helper()
	if res.IsError {
		t.Fatalf("tool returned an error: %v", res.Content)
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structured content: %v", err)
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		t.Fatalf("unmarshal structured content: %v\n%s", err, raw)
	}
}

type rolesResult struct {
	Roles []struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Provider    string `json:"provider"`
		Skill       string `json:"skill"`
		URL         string `json:"url"`
	} `json:"roles"`
	Warnings []string `json:"warnings"`
}

// readSkillText calls read_skill and returns the SKILL.md it serves.
func readSkillText(t *testing.T, session *mcp.ClientSession, uri string) string {
	t.Helper()
	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "read_skill",
		Arguments: map[string]any{"uri": uri},
	})
	if err != nil {
		t.Fatalf("read_skill{uri: %q}: %v", uri, err)
	}
	if res.IsError {
		t.Fatalf("read_skill{uri: %q} returned a tool error: %v", uri, res.Content)
	}
	if len(res.Content) != 1 {
		t.Fatalf("read_skill returned %d content items, want 1", len(res.Content))
	}
	txt, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("read_skill content is %T, want text", res.Content[0])
	}
	return txt.Text
}

// TestMCPDiscovery_ToolsAndListRoles connects to the discovery endpoint,
// verifies both tools are advertised, and that list_roles returns the roles
// the default JWT identity can assume.
func TestMCPDiscovery_ToolsAndListRoles(t *testing.T) {
	session := connectDiscovery(t)
	ctx := context.Background()

	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	got := map[string]bool{}
	for _, tl := range tools.Tools {
		got[tl.Name] = true
	}
	for _, want := range []string{"list_roles", "read_skill"} {
		if !got[want] {
			t.Errorf("tools/list missing %q; got %v", want, got)
		}
	}
	if got["get_skill"] {
		t.Errorf("tools/list still advertises the removed get_skill")
	}

	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "list_roles"})
	if err != nil {
		t.Fatalf("call list_roles: %v", err)
	}
	var roles rolesResult
	decodeStructured(t, res, &roles)
	if len(roles.Roles) == 0 {
		t.Fatalf("expected at least one role for the default JWT; got none")
	}
	for _, r := range roles.Roles {
		if r.Name == "" {
			t.Errorf("role with empty name: %#v", r)
		}
	}
}

// TestMCPDiscovery_ReadSkillByURI reads a skill by URI. The e2e cluster mounts
// the vault provider, which seeds the "vault" skill.
func TestMCPDiscovery_ReadSkillByURI(t *testing.T) {
	session := connectDiscovery(t)

	md := readSkillText(t, session, "skill://vault/SKILL.md")
	if !strings.HasPrefix(md, "---\nname: vault\n") {
		t.Fatalf("SKILL.md does not open with the vault frontmatter:\n%s", md)
	}
	if !strings.Contains(md, "\n---\n\n#") {
		t.Errorf("SKILL.md has no body after its frontmatter:\n%s", md)
	}
}

// TestMCPDiscovery_FullLoop walks the roles.md discovery loop: create a role
// wired to the vault provider, list roles, take the role's skill URI and URL,
// then read that skill.
func TestMCPDiscovery_FullLoop(t *testing.T) {
	port := h.GetLeaderPort(t)

	const roleName = "e2e-mcp-discovery"
	body := `{"token_policies":["vault-gateway-access"],"cred_spec_name":"vault-token-reader","user_claim":"sub","token_ttl":300,"description":"read app secrets through Vault","provider_path":"vault"}`
	status, respBody := h.APIRequest(t, "POST", "auth/jwt/role/"+roleName, port, body)
	if status != 200 && status != 201 && status != 204 {
		t.Fatalf("create role failed: status %d, body %s", status, string(respBody))
	}
	t.Cleanup(func() {
		h.APIRequest(t, "DELETE", "auth/jwt/role/"+roleName, port, "")
	})

	session := connectDiscovery(t)
	ctx := context.Background()

	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "list_roles"})
	if err != nil {
		t.Fatalf("call list_roles: %v", err)
	}
	var roles rolesResult
	decodeStructured(t, res, &roles)

	found := false
	for _, r := range roles.Roles {
		if r.Name != roleName {
			continue
		}
		found = true
		if r.Provider != "vault" {
			t.Errorf("provider = %q, want vault", r.Provider)
		}
		if want := "/v1/vault/role/" + roleName + "/gateway/"; r.URL != want {
			t.Errorf("url = %q, want %q", r.URL, want)
		}
		if r.Skill != "skill://vault/SKILL.md" {
			t.Fatalf("skill = %q, want the vault provider's skill://vault/SKILL.md", r.Skill)
		}
		if md := readSkillText(t, session, r.Skill); !strings.HasPrefix(md, "---\nname: vault\n") {
			t.Errorf("the role's skill does not read back as vault:\n%s", md)
		}
	}
	if !found {
		t.Fatalf("role %q not found in list_roles output; warnings: %v", roleName, roles.Warnings)
	}
	for _, w := range roles.Warnings {
		if strings.Contains(w, roleName) {
			t.Errorf("unexpected warning for %q: %s", roleName, w)
		}
	}
}
