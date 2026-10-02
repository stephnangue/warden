package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// connectSkillsClient dials the discovery endpoint with a client that can send
// the Skills extension's methods.
func connectSkillsClient(t *testing.T, srv *httptest.Server, bearer string) *mcp.ClientSession {
	t.Helper()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-host", Version: "1.0.0"}, nil)
	require.NoError(t, mcp.AddSendingCustomMethod[*skillsListParams, *skillsListResult](client, "skills/list"))
	require.NoError(t, mcp.AddSendingCustomMethod[*skillsGetParams, *skillsGetResult](client, "skills/get"))
	transport := &mcp.StreamableClientTransport{
		Endpoint: srv.URL + "/v1/sys/mcp",
		HTTPClient: &http.Client{Transport: mcpHeaderRoundTripper{
			base:    http.DefaultTransport,
			headers: map[string]string{"Authorization": bearerHeader(bearer)},
		}},
		DisableStandaloneSSE: true,
	}
	session, err := client.Connect(context.Background(), transport, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func listSkills(t *testing.T, session *mcp.ClientSession) *skillsListResult {
	t.Helper()
	res, err := mcp.CallCustomMethod[*skillsListParams, *skillsListResult](
		context.Background(), session, "skills/list", &skillsListParams{})
	require.NoError(t, err)
	return res
}

func getSkill(session *mcp.ClientSession, uri string) (*skillsGetResult, error) {
	return mcp.CallCustomMethod[*skillsGetParams, *skillsGetResult](
		context.Background(), session, "skills/get", &skillsGetParams{URI: uri})
}

func readSkillResource(session *mcp.ClientSession, uri string) (*mcp.ReadResourceResult, error) {
	return session.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: uri})
}

func skillNames(res *skillsListResult) []string {
	names := make([]string, len(res.Skills))
	for i, s := range res.Skills {
		names[i] = s.Frontmatter.Name
	}
	return names
}

// setupSkillsDiscovery mounts jwt/ and the vault provider, gives the identity
// two roles, and seeds a provider skill, a custom skill with a requires cycle,
// a foundation skill and a skill no role references. The mock serves the same
// roles to every bearer, so tests change the identity's roles by editing the
// returned mock.
func setupSkillsDiscovery(t *testing.T) (*Core, *introspectMock) {
	t.Helper()
	c, ctx, ctrl := setupDiscovery(t)
	mountDiscoveryProvider(t, c, ctx, "vault", "vault/", "auth/jwt/", "")
	seedTestSkill(t, c, ctx, "vault")
	seedTestSkill(t, c, ctx, "slack")
	for _, s := range []*Skill{
		{Name: "runbook", Description: "on-call runbook", Category: SkillCategoryCustom, Body: "# runbook", Requires: []string{"escalation"}},
		{Name: "escalation", Description: "who to page", Category: SkillCategoryCustom, Body: "# escalation", Requires: []string{"runbook"}},
		{Name: "troubleshooting", Description: "common failures", Category: SkillCategoryTroubleshooting, Body: "# troubleshooting"},
	} {
		require.NoError(t, c.skillStore.Create(ctx, s))
	}
	ctrl.rolesByMount["auth/jwt/"] = []map[string]any{
		{"name": "read-secret", "provider_path": "vault/"},
		{"name": "on-call", "skill": "runbook"},
	}
	return c, ctrl
}

func TestSkillsExtension_DeclaredCapability(t *testing.T) {
	c, _ := setupSkillsDiscovery(t)
	session := connectSkillsClient(t, startMCPTestServer(t, c, nil), "eyJ.any.token")

	caps := session.InitializeResult().Capabilities
	require.NotNil(t, caps)
	assert.Contains(t, caps.Extensions, skillsExtension)
	assert.NotNil(t, caps.Resources, "the extension requires the resources capability")
	assert.NotNil(t, caps.Tools)
}

// skills/list returns exactly the identity's visible set: its roles' skills,
// the requires closure (cycle included) and the foundation skills — and not a
// seeded skill no role points at.
func TestSkillsList_VisibleSet(t *testing.T) {
	c, _ := setupSkillsDiscovery(t)
	session := connectSkillsClient(t, startMCPTestServer(t, c, nil), "eyJ.any.token")

	res := listSkills(t, session)
	assert.Equal(t, "complete", res.ResultType)
	assert.Equal(t, "private", res.CacheScope, "the listing depends on the identity")
	assert.Equal(t, []string{"escalation", "runbook", "troubleshooting", "vault"}, skillNames(res))
}

// Each entry's digest and size describe exactly the bytes resources/read and
// read_skill serve, and its frontmatter is the file's.
func TestSkillsList_EntryMatchesServedBytes(t *testing.T) {
	c, _ := setupSkillsDiscovery(t)
	session := connectSkillsClient(t, startMCPTestServer(t, c, nil), "eyJ.any.token")

	for _, e := range listSkills(t, session).Skills {
		t.Run(e.Frontmatter.Name, func(t *testing.T) {
			assert.Equal(t, skillURI(e.Frontmatter.Name), e.URI)
			require.Len(t, e.Resources, 1)
			assert.Equal(t, e.URI, e.Resources[0].URI)

			read, err := readSkillResource(session, e.URI)
			require.NoError(t, err)
			assert.Equal(t, "private", read.CacheScope, "whether the URI resolves depends on the identity")
			require.Len(t, read.Contents, 1)
			body := []byte(read.Contents[0].Text)
			assert.Equal(t, "text/markdown", read.Contents[0].MIMEType)
			sum := sha256.Sum256(body)
			assert.Equal(t, "sha256:"+hex.EncodeToString(sum[:]), e.Resources[0].Digest)
			assert.Equal(t, len(body), e.Resources[0].Size)

			fm, _ := splitRendered(t, body)
			assert.Equal(t, asJSONMap(t, e.Frontmatter), fm)

			tool := callReadSkill(t, session, map[string]any{"uri": e.URI})
			require.False(t, tool.IsError, "%v", tool.Content)
			assert.Equal(t, string(body), tool.Content[0].(*mcp.TextContent).Text)

			got, err := getSkill(session, e.URI)
			require.NoError(t, err)
			assert.Equal(t, "complete", got.ResultType)
			assert.Equal(t, e, got.Skill)
		})
	}
}

// A skill the identity cannot see is answered exactly like one that does not
// exist, on every entry point.
func TestSkills_InvisibleIsUnknown(t *testing.T) {
	c, _ := setupSkillsDiscovery(t)
	session := connectSkillsClient(t, startMCPTestServer(t, c, nil), "eyJ.any.token")

	for _, uri := range []string{"skill://slack/SKILL.md", "skill://nope/SKILL.md", "skill://mcp_aws/SKILL.md"} {
		t.Run(uri, func(t *testing.T) {
			_, err := getSkill(session, uri)
			var rpcErr *jsonrpc.Error
			require.True(t, errors.As(err, &rpcErr), "got %v", err)
			assert.Equal(t, int64(jsonrpc.CodeInvalidParams), rpcErr.Code)
			assert.Equal(t, `unknown skill URI "`+uri+`"`, rpcErr.Message)

			_, err = readSkillResource(session, uri)
			require.True(t, errors.As(err, &rpcErr), "got %v", err)
			assert.Equal(t, int64(mcp.CodeResourceNotFound), rpcErr.Code)
			assert.Equal(t, "Resource not found", rpcErr.Message)

			// mcp_aws is malformed, so read_skill names the syntax; the
			// invisible and the nonexistent skill read identically.
			tool := callReadSkill(t, session, map[string]any{"uri": uri})
			require.True(t, tool.IsError)
			if uri != "skill://mcp_aws/SKILL.md" {
				assert.Equal(t, `skill "`+uri+`" not found`, tool.Content[0].(*mcp.TextContent).Text)
			}
		})
	}
}

// No cursor is ever issued, so a cursor is invalid rather than ignored.
func TestSkillsList_RejectsCursor(t *testing.T) {
	c, _ := setupSkillsDiscovery(t)
	session := connectSkillsClient(t, startMCPTestServer(t, c, nil), "eyJ.any.token")

	_, err := mcp.CallCustomMethod[*skillsListParams, *skillsListResult](
		context.Background(), session, "skills/list", &skillsListParams{Cursor: "garbage"})
	var rpcErr *jsonrpc.Error
	require.True(t, errors.As(err, &rpcErr), "got %v", err)
	assert.Equal(t, int64(jsonrpc.CodeInvalidParams), rpcErr.Code)
}

// A client on an older protocol revision, without per-request _meta, reaches
// the extension's methods with its identity resolved.
func TestSkillsList_LegacyProtocolClient(t *testing.T) {
	c, _ := setupSkillsDiscovery(t)
	srv := startMCPTestServer(t, c, nil)

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/sys/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"skills/list","params":{}}`))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2025-11-25")
	req.Header.Set("Authorization", "Bearer eyJ.any.token")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "body: %s", raw)

	var parsed struct {
		Result skillsListResult `json:"result"`
	}
	require.NoError(t, json.Unmarshal(raw, &parsed), "body: %s", raw)
	assert.Equal(t, []string{"escalation", "runbook", "troubleshooting", "vault"}, skillNames(&parsed.Result))
}

// Changing the identity's roles changes what it sees.
func TestSkills_VisibilityFollowsRoles(t *testing.T) {
	c, ctrl := setupSkillsDiscovery(t)
	srv := startMCPTestServer(t, c, nil)
	ctrl.rolesByMount["auth/jwt/"] = []map[string]any{{"name": "slacker", "skill": "slack"}}
	session := connectSkillsClient(t, srv, "eyJ.any.token")

	assert.Equal(t, []string{"slack", "troubleshooting"}, skillNames(listSkills(t, session)))
	_, err := getSkill(session, "skill://vault/SKILL.md")
	var rpcErr *jsonrpc.Error
	require.True(t, errors.As(err, &rpcErr), "vault is no longer reachable from this identity's roles; got %v", err)
	assert.Equal(t, int64(jsonrpc.CodeInvalidParams), rpcErr.Code)
}

// Without an identity there is nothing to scope the skills to.
func TestSkills_NoCredential(t *testing.T) {
	c, _ := setupSkillsDiscovery(t)
	session := connectSkillsClient(t, startMCPTestServer(t, c, nil), "")

	_, err := mcp.CallCustomMethod[*skillsListParams, *skillsListResult](
		context.Background(), session, "skills/list", &skillsListParams{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "JWT bearer token or TLS client certificate")

	_, err = readSkillResource(session, "skill://troubleshooting/SKILL.md")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "JWT bearer token or TLS client certificate",
		"even a foundation skill needs an identity to scope it")
}

// The render cache serves the same rendering while a skill is unchanged, then
// the new content — including for a skill deleted and recreated under the
// same name, which restarts at version 1 — and Delete drops the entry.
func TestSkillRenderCache_FollowsWrites(t *testing.T) {
	c, ctx, _ := setupDiscovery(t)
	require.NoError(t, c.skillStore.Create(ctx, &Skill{Name: "x", Description: "d", Category: SkillCategoryCustom, Body: "one"}))
	get := func() *renderedSkill {
		s, err := c.skillStore.Get(ctx, "x")
		require.NoError(t, err)
		r, err := c.skillRenders.get(s)
		require.NoError(t, err)
		return r
	}

	first := get()
	assert.Contains(t, string(first.markdown), "one")
	assert.Same(t, first, get(), "an unchanged skill is served from the cache")

	_, err := c.skillStore.Update(ctx, "x", &Skill{Body: "two"})
	require.NoError(t, err)
	second := get()
	assert.NotSame(t, first, second)
	assert.Contains(t, string(second.markdown), "two")

	require.NoError(t, c.skillStore.Delete(ctx, "x"))
	_, cached := c.skillRenders.m.Load("x")
	assert.False(t, cached, "Delete drops the cache entry")

	require.NoError(t, c.skillStore.Create(ctx, &Skill{Name: "x", Description: "d", Category: SkillCategoryCustom, Body: "three"}))
	assert.Contains(t, string(get().markdown), "three")
}
