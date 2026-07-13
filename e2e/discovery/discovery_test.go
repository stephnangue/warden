//go:build e2e

// Package discovery exercises Warden's own MCP server — the discovery
// interface at /v1/sys/mcp (list_roles + get_skill) — end to end against the
// live cluster, following the roles.md scenario: an agent connects, lists the
// roles its identity can assume, reads a skill name out of a role description,
// and fetches that skill — the recipe that teaches it how to drive the
// provider through the gateway.
package discovery

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"regexp"
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
	} `json:"roles"`
	Warnings []string `json:"warnings"`
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
	for _, want := range []string{"list_roles", "get_skill"} {
		if !got[want] {
			t.Errorf("tools/list missing %q; got %v", want, got)
		}
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
	// The projection drops auth_path — each entry is {name, description}.
	for _, r := range roles.Roles {
		if r.Name == "" {
			t.Errorf("role with empty name: %#v", r)
		}
	}
}

// TestMCPDiscovery_GetSkillByName fetches a skill by name. The e2e cluster
// mounts the vault provider, which seeds the "vault" skill.
func TestMCPDiscovery_GetSkillByName(t *testing.T) {
	session := connectDiscovery(t)
	ctx := context.Background()

	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_skill",
		Arguments: map[string]any{"skill": "vault"},
	})
	if err != nil {
		t.Fatalf("get_skill by name: %v", err)
	}
	var skill map[string]any
	decodeStructured(t, res, &skill)
	if skill["name"] != "vault" {
		t.Fatalf("skill vault resolved to %v, want vault", skill["name"])
	}
	if bodyStr, _ := skill["body"].(string); bodyStr == "" {
		t.Errorf("resolved skill has an empty body")
	}
}

// skillNameRe extracts the skill name an operator embeds in a role
// description, e.g. "read secrets (skill: vault)".
var skillNameRe = regexp.MustCompile(`skill:\s*([A-Za-z0-9._-]+)`)

// TestMCPDiscovery_FullLoop walks the roles.md discovery loop: create a role
// whose description embeds a skill name, list roles, parse the name out of the
// description, then fetch that skill.
func TestMCPDiscovery_FullLoop(t *testing.T) {
	port := h.GetLeaderPort(t)

	const roleName = "e2e-mcp-discovery"
	body := `{"token_policies":["vault-gateway-access"],"cred_spec_name":"vault-token-reader","user_claim":"sub","token_ttl":300,"description":"read app secrets through Vault (skill: vault)"}`
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

	var skillName string
	for _, r := range roles.Roles {
		if r.Name != roleName {
			continue
		}
		m := skillNameRe.FindStringSubmatch(r.Description)
		if m == nil {
			t.Fatalf("role %q description %q had no parseable skill name", roleName, r.Description)
		}
		skillName = m[1]
	}
	if skillName == "" {
		t.Fatalf("role %q not found in list_roles output", roleName)
	}

	skillRes, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_skill",
		Arguments: map[string]any{"skill": skillName},
	})
	if err != nil {
		t.Fatalf("get_skill{skill: %q}: %v", skillName, err)
	}
	var skill map[string]any
	decodeStructured(t, skillRes, &skill)
	if skill["name"] != "vault" {
		t.Fatalf("parsed skill name %q resolved to skill %v, want vault", skillName, skill["name"])
	}
	if bodyStr, _ := skill["body"].(string); bodyStr == "" {
		t.Errorf("resolved skill has an empty body")
	}
}
