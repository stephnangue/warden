package core

import (
	"context"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
)

// discoveryMockProvider is a transparent provider whose role URL suffix can be
// overridden, standing in for the providers list_roles resolves.
type discoveryMockProvider struct {
	mockTransparentModeProvider
	suffix string // "" → logical.DefaultRoleURLSuffix
}

func (p *discoveryMockProvider) RoleURLSuffix(role string) string {
	if p.suffix == "" {
		return logical.DefaultRoleURLSuffix(role)
	}
	return p.suffix
}

// discoveryProviderFactory returns a factory for a provider bound to
// autoAuthPath ("" leaves it without one).
func discoveryProviderFactory(autoAuthPath, suffix string) logical.Factory {
	return func(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
		p := &discoveryMockProvider{suffix: suffix}
		p.transparentMode = autoAuthPath != ""
		p.autoAuthPath = autoAuthPath
		if err := p.Setup(ctx, conf); err != nil {
			return nil, err
		}
		p.setupRouter()
		return p, nil
	}
}

// mountDiscoveryProvider mounts a provider of type typ at path in the root
// namespace.
func mountDiscoveryProvider(t *testing.T, c *Core, ctx context.Context, typ, path, autoAuthPath, suffix string) {
	t.Helper()
	c.providers[typ] = discoveryProviderFactory(autoAuthPath, suffix)
	require.NoError(t, c.mount(ctx, &MountEntry{Class: mountClassProvider, Type: typ, Path: path}))
}

// listRolesFor starts the discovery server and returns list_roles' output for
// a bearer identity.
func listRolesFor(t *testing.T, c *Core) listRolesOutput {
	t.Helper()
	srv := startMCPTestServer(t, c, nil)
	session := connectMCP(t, srv, "eyJ.any.token")
	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "list_roles"})
	require.NoError(t, err)
	return decodeListRoles(t, res)
}

// setupDiscovery mounts a JWT auth method at jwt/ whose roles the returned
// mock serves.
func setupDiscovery(t *testing.T) (*Core, context.Context, *introspectMock) {
	t.Helper()
	_, ctx, c := setupTestSystemBackend(t)
	ctrl := newIntrospectMock()
	c.authMethods["jwt"] = ctrl.factory()
	require.NoError(t, c.mount(ctx, &MountEntry{Class: mountClassAuth, Type: "jwt", Path: "jwt/"}))
	return c, ctx, ctrl
}

func rolesByName(out listRolesOutput) map[string]mcpRole {
	m := make(map[string]mcpRole, len(out.Roles))
	for _, r := range out.Roles {
		m[r.Name] = r
	}
	return m
}

// Each provider shape yields the URL its gateway accepts, and the skill
// defaults to the provider type's skill unless the role names its own.
func TestListRoles_ResolvesSkillAndURL(t *testing.T) {
	c, ctx, ctrl := setupDiscovery(t)
	mountDiscoveryProvider(t, c, ctx, "vault", "vault/", "auth/jwt/", "")
	mountDiscoveryProvider(t, c, ctx, "aws", "aws/", "auth/jwt/", "gateway")
	mountDiscoveryProvider(t, c, ctx, "rds", "rds-prod/", "auth/jwt/", "access/")
	mountDiscoveryProvider(t, c, ctx, "mcp_aws", "mcp-aws/", "auth/jwt/", "")
	seedTestSkill(t, c, ctx, "vault")
	seedTestSkill(t, c, ctx, "aws")
	seedTestSkill(t, c, ctx, "rds")
	seedTestSkill(t, c, ctx, "gh-repo-creator")
	require.NoError(t, c.skillStore.Create(ctx, &Skill{
		Name: "mcp-aws", Description: "aws mcp", Category: SkillCategoryProviderGuide,
		Provider: "mcp_aws", Body: "# mcp-aws",
	}))

	ctrl.rolesByMount["auth/jwt/"] = []map[string]any{
		{"name": "read-secret", "description": "read app secrets", "provider_path": "vault/"},
		{"name": "repo-creator", "description": "create the repo", "provider_path": "vault/", "skill": "gh-repo-creator"},
		{"name": "s3-reader", "description": "read S3", "provider_path": "aws/"},
		{"name": "db-reader", "description": "read the DB", "provider_path": "rds-prod/"},
		{"name": "aws-mcp", "description": "aws mcp", "provider_path": "mcp-aws/"},
		{"name": "skill-only", "description": "a recipe, no provider", "skill": "gh-repo-creator"},
		{"name": "plain", "description": "no discovery fields"},
	}

	out := listRolesFor(t, c)
	assert.Empty(t, out.Warnings)
	roles := rolesByName(out)

	assert.Equal(t, mcpRole{Name: "read-secret", Description: "read app secrets", Provider: "vault",
		Skill: "skill://vault/SKILL.md", URL: "/v1/vault/role/read-secret/gateway/"}, roles["read-secret"])
	assert.Equal(t, "skill://gh-repo-creator/SKILL.md", roles["repo-creator"].Skill)
	assert.Equal(t, "/v1/vault/role/repo-creator/gateway/", roles["repo-creator"].URL)
	assert.Equal(t, "/v1/aws/gateway", roles["s3-reader"].URL)
	assert.Equal(t, "skill://aws/SKILL.md", roles["s3-reader"].Skill)
	assert.Equal(t, "/v1/rds-prod/access/", roles["db-reader"].URL)
	assert.Equal(t, "mcp_aws", roles["aws-mcp"].Provider)
	assert.Equal(t, "skill://mcp-aws/SKILL.md", roles["aws-mcp"].Skill, "the default skill is the hyphenated type")
	assert.Equal(t, mcpRole{Name: "skill-only", Description: "a recipe, no provider",
		Skill: "skill://gh-repo-creator/SKILL.md"}, roles["skill-only"])
	assert.Equal(t, mcpRole{Name: "plain", Description: "no discovery fields"}, roles["plain"])
}

// Every way a role's discovery fields can fail to resolve leaves the role
// listed without the unresolved fields and explains why in a warning.
func TestListRoles_UnresolvedFieldsBecomeWarnings(t *testing.T) {
	c, ctx, ctrl := setupDiscovery(t)
	require.NoError(t, c.mount(ctx, &MountEntry{Class: mountClassAuth, Type: "jwt", Path: "jwt-b/"}))
	mountDiscoveryProvider(t, c, ctx, "vault", "vault/", "auth/jwt/", "")
	mountDiscoveryProvider(t, c, ctx, "anthropic", "anthropic/", "auth/jwt/", "")
	mountDiscoveryProvider(t, c, ctx, "github", "github/", "", "")
	// The gateway resolves auto_auth_path verbatim and "auth/jwt" does not
	// reach the auth/jwt/ mount, so discovery must not vouch for a URL here.
	mountDiscoveryProvider(t, c, ctx, "slack", "slack/", "auth/jwt", "")
	seedTestSkill(t, c, ctx, "vault")
	seedTestSkill(t, c, ctx, "custom")

	ctrl.rolesByMount["auth/jwt/"] = []map[string]any{
		{"name": "gone", "provider_path": "vault-old/"},
		{"name": "no-default-skill", "provider_path": "anthropic/"},
		{"name": "custom-on-skill-less-type", "provider_path": "anthropic/", "skill": "custom"},
		{"name": "missing-skill", "provider_path": "vault/", "skill": "nope"},
		{"name": "no-auto-auth", "provider_path": "github/"},
		{"name": "slashless-auto-auth", "provider_path": "slack/"},
	}
	ctrl.rolesByMount["auth/jwt-b/"] = []map[string]any{
		{"name": "wrong-auth", "provider_path": "vault/"},
	}

	out := listRolesFor(t, c)
	roles := rolesByName(out)
	warnings := strings.Join(out.Warnings, "\n")

	assert.Equal(t, mcpRole{Name: "gone"}, roles["gone"])
	assert.Contains(t, warnings, `role "gone": provider_path "vault-old/" is not a provider mount in this namespace`)

	assert.Equal(t, "/v1/anthropic/role/no-default-skill/gateway/", roles["no-default-skill"].URL)
	assert.Empty(t, roles["no-default-skill"].Skill, "anthropic ships no skill, and that is not a warning")
	assert.NotContains(t, warnings, "no-default-skill")

	assert.Equal(t, "skill://custom/SKILL.md", roles["custom-on-skill-less-type"].Skill,
		"an explicit skill applies whether or not the provider type ships one")
	assert.NotContains(t, warnings, "custom-on-skill-less-type")

	assert.Equal(t, "/v1/vault/role/missing-skill/gateway/", roles["missing-skill"].URL)
	assert.Empty(t, roles["missing-skill"].Skill, "a missing explicit skill does not fall back to the default")
	assert.Contains(t, warnings, `role "missing-skill": skill "nope" does not exist`)

	assert.Empty(t, roles["no-auto-auth"].URL)
	assert.Contains(t, warnings, `role "no-auto-auth": provider "github/" has no auto_auth_path`)

	assert.Empty(t, roles["slashless-auto-auth"].URL)
	assert.Contains(t, warnings, `role "slashless-auto-auth": provider "slack/" does not authenticate through this role's auth mount`)

	assert.Empty(t, roles["wrong-auth"].URL)
	assert.Empty(t, roles["wrong-auth"].Provider)
	assert.Contains(t, warnings, `role "wrong-auth": provider "vault/" does not authenticate through this role's auth mount`)

	// Warnings name roles and provider mounts, never auth mount paths.
	assert.NotContains(t, warnings, "auth/")
	assert.NotContains(t, warnings, "jwt-b/")
}

// The URL carries the namespace the caller selected.
func TestListRoles_URLCarriesNamespace(t *testing.T) {
	c, ctx, ctrl := setupDiscovery(t)
	ns := &namespace.Namespace{Path: "team-data/"}
	require.NoError(t, c.namespaceStore.SetNamespace(ctx, ns))
	nsCtx := namespace.ContextWithNamespace(context.Background(), ns)
	require.NoError(t, c.mount(nsCtx, &MountEntry{Class: mountClassAuth, Type: "jwt", Path: "jwt/"}))
	mountDiscoveryProvider(t, c, nsCtx, "vault", "vault/", "auth/jwt/", "")
	ctrl.rolesByMount["team-data/auth/jwt/"] = []map[string]any{
		{"name": "read-secret", "provider_path": "vault/"},
	}

	srv := startMCPTestServer(t, c, nil)
	session := connectMCPWithHeaders(t, srv, map[string]string{
		"Authorization":      "Bearer eyJ.any.token",
		"X-Warden-Namespace": "team-data",
	})
	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "list_roles"})
	require.NoError(t, err)
	out := decodeListRoles(t, res)

	require.Len(t, out.Roles, 1)
	assert.Equal(t, "/v1/team-data/vault/role/read-secret/gateway/", out.Roles[0].URL)
}

func TestParseSkillURI(t *testing.T) {
	name, err := parseSkillURI("skill://mcp-aws/SKILL.md")
	require.NoError(t, err)
	assert.Equal(t, "mcp-aws", name)

	for _, bad := range []string{
		"", "vault", "skill://vault", "skill://vault/", "skill://vault/README.md",
		"skill://mcp_aws/SKILL.md", "skill://a/b/SKILL.md", "file://vault/SKILL.md",
	} {
		_, err := parseSkillURI(bad)
		assert.Error(t, err, bad)
	}
}
