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
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
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
	if err := mcp.AddSendingCustomMethod[*skillsListParams, *skillsListResult](client, "skills/list"); err != nil {
		t.Fatal(err)
	}
	if err := mcp.AddSendingCustomMethod[*skillsGetParams, *skillsGetResult](client, "skills/get"); err != nil {
		t.Fatal(err)
	}
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

// Skills extension (io.modelcontextprotocol/skills) wire types.
type skillEntry struct {
	URI         string         `json:"uri"`
	Frontmatter map[string]any `json:"frontmatter"`
	Resources   []struct {
		URI    string `json:"uri"`
		Digest string `json:"digest"`
		Size   int    `json:"size"`
	} `json:"resources"`
}

type skillsListParams struct {
	mcp.ParamsBase
}

type skillsListResult struct {
	mcp.ResultBase
	Skills []skillEntry `json:"skills"`
}

type skillsGetParams struct {
	mcp.ParamsBase
	URI string `json:"uri"`
}

type skillsGetResult struct {
	mcp.ResultBase
	Skill skillEntry `json:"skill"`
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

// createDiscoveryRole creates a JWT role the default identity can assume,
// wired to the vault provider (the e2e cluster mounts it, which seeds the
// "vault" skill), and removes it when the test ends.
func createDiscoveryRole(t *testing.T, port int, roleName string) {
	t.Helper()
	body := `{"token_policies":["vault-gateway-access"],"cred_spec_name":"vault-token-reader","user_claim":"sub","token_ttl":300,"description":"read app secrets through Vault","provider_path":"vault"}`
	status, respBody := h.APIRequest(t, "POST", "auth/jwt/role/"+roleName, port, body)
	if status != 200 && status != 201 && status != 204 {
		t.Fatalf("create role failed: status %d, body %s", status, string(respBody))
	}
	t.Cleanup(func() {
		h.APIRequest(t, "DELETE", "auth/jwt/role/"+roleName, port, "")
	})
}

// TestMCPDiscovery_SkillsExtension drives the Skills extension: the identity
// sees the skill its role reaches, the listed digest matches the bytes served,
// and a skill no role of the identity reaches is unknown to it.
func TestMCPDiscovery_SkillsExtension(t *testing.T) {
	port := h.GetLeaderPort(t)
	createDiscoveryRole(t, port, "e2e-mcp-skills")

	const hidden = "e2e-unreferenced-skill"
	status, respBody := h.APIRequest(t, "POST", "sys/skills/"+hidden, port,
		`{"name":"`+hidden+`","description":"no role points here","category":"custom","body":"# hidden"}`)
	if status != 200 && status != 201 && status != 204 {
		t.Fatalf("create skill failed: status %d, body %s", status, string(respBody))
	}
	t.Cleanup(func() { h.APIRequest(t, "DELETE", "sys/skills/"+hidden, port, "") })

	session := connectDiscovery(t)
	ctx := context.Background()

	if _, ok := session.InitializeResult().Capabilities.Extensions["io.modelcontextprotocol/skills"]; !ok {
		t.Fatalf("the skills extension is not declared: %+v", session.InitializeResult().Capabilities)
	}

	list, err := mcp.CallCustomMethod[*skillsListParams, *skillsListResult](ctx, session, "skills/list", &skillsListParams{})
	if err != nil {
		t.Fatalf("skills/list: %v", err)
	}
	var vault *skillEntry
	for i, s := range list.Skills {
		switch s.URI {
		case "skill://vault/SKILL.md":
			vault = &list.Skills[i]
		case "skill://" + hidden + "/SKILL.md":
			t.Errorf("skills/list shows %s, which no role of this identity reaches", hidden)
		}
	}
	if vault == nil {
		t.Fatalf("skills/list misses the vault skill its role reaches: %+v", list.Skills)
	}

	read, err := session.ReadResource(ctx, &mcp.ReadResourceParams{URI: vault.URI})
	if err != nil {
		t.Fatalf("resources/read %s: %v", vault.URI, err)
	}
	md := read.Contents[0].Text
	if !strings.HasPrefix(md, "---\nname: vault\n") {
		t.Fatalf("SKILL.md does not open with the vault frontmatter:\n%s", md)
	}
	sum := sha256.Sum256([]byte(md))
	if want := "sha256:" + hex.EncodeToString(sum[:]); len(vault.Resources) != 1 ||
		vault.Resources[0].Digest != want || vault.Resources[0].Size != len(md) {
		t.Errorf("listed resources %+v do not describe the %d bytes served (digest %s)", vault.Resources, len(md), want)
	}
	if tool := readSkillText(t, session, vault.URI); tool != md {
		t.Errorf("read_skill and resources/read serve different bytes")
	}

	_, err = mcp.CallCustomMethod[*skillsGetParams, *skillsGetResult](ctx, session, "skills/get",
		&skillsGetParams{URI: "skill://" + hidden + "/SKILL.md"})
	var rpcErr *jsonrpc.Error
	if !errors.As(err, &rpcErr) || rpcErr.Code != jsonrpc.CodeInvalidParams {
		t.Errorf("skills/get for %s, which no role of this identity reaches: got %v, want a -32602 error", hidden, err)
	}
}

// TestMCPDiscovery_FullLoop walks the roles.md discovery loop: create a role
// wired to the vault provider, list roles, take the role's skill URI and URL,
// then read that skill.
func TestMCPDiscovery_FullLoop(t *testing.T) {
	port := h.GetLeaderPort(t)
	const roleName = "e2e-mcp-discovery"
	createDiscoveryRole(t, port, roleName)

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
