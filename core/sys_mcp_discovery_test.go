package core

import (
	"context"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

// mountDiscoveryProvider mounts a provider of type typ at path in the
// namespace of ctx.
func mountDiscoveryProvider(t *testing.T, c *Core, ctx context.Context, typ, path, autoAuthPath, suffix string) {
	t.Helper()
	c.providers[typ] = discoveryProviderFactory(autoAuthPath, suffix)
	require.NoError(t, c.mount(ctx, &MountEntry{Class: mountClassProvider, Type: typ, Path: path}))
}

// listRolesFor returns list_roles' output for a bearer identity in the env's
// namespace.
func listRolesFor(t *testing.T, e *discEnv) listRolesOutput {
	t.Helper()
	roles, warnings, err := e.listRoles("eyJ.any.token")
	require.NoError(t, err)
	return listRolesOutput{Roles: roles, Warnings: warnings}
}

// setupDiscovery returns an env in the namespace team/, whose auto_auth_path
// is auth/jwt/, with an auth mount at jwt/ admitting every credential.
func setupDiscovery(t *testing.T) *discEnv {
	t.Helper()
	e := newDiscEnv(t, "team/", "auth/jwt/")
	e.mountAuth("jwt/")
	return e
}

func rolesByName(out listRolesOutput) map[string]mcpRole {
	m := make(map[string]mcpRole, len(out.Roles))
	for _, r := range out.Roles {
		m[r.Name] = r
	}
	return m
}

// Each provider shape yields the URL its gateway accepts, and the skill
// defaults to the provider type's skill unless the role names its own. A role
// without a provider is reached at the namespace's auto_auth_path.
func TestListRoles_ResolvesSkillAndURL(t *testing.T) {
	e := setupDiscovery(t)
	ctx := e.ctx
	mountDiscoveryProvider(t, e.c, ctx, "vault", "vault/", "auth/jwt/", "")
	mountDiscoveryProvider(t, e.c, ctx, "aws", "aws/", "auth/jwt/", "gateway")
	mountDiscoveryProvider(t, e.c, ctx, "rds", "rds-prod/", "auth/jwt/", "access/")
	mountDiscoveryProvider(t, e.c, ctx, "mcp_aws", "mcp-aws/", "auth/jwt/", "")
	seedTestSkill(t, e.c, rootCtx(), "vault")
	seedTestSkill(t, e.c, rootCtx(), "aws")
	seedTestSkill(t, e.c, rootCtx(), "rds")
	seedTestSkill(t, e.c, rootCtx(), "gh-repo-creator")
	require.NoError(t, e.c.skillStore.Create(rootCtx(), &Skill{
		Name: "mcp-aws", Description: "aws mcp", Category: SkillCategoryProviderGuide,
		Provider: "mcp_aws", Body: "# mcp-aws",
	}))

	e.grant("all", []string{"auth/jwt/"},
		&logical.Role{Name: "read-secret", Description: "read app secrets", ProviderPath: "vault/"},
		&logical.Role{Name: "repo-creator", Description: "create the repo", ProviderPath: "vault/", Skill: "gh-repo-creator"},
		&logical.Role{Name: "s3-reader", Description: "read S3", ProviderPath: "aws/"},
		&logical.Role{Name: "db-reader", Description: "read the DB", ProviderPath: "rds-prod/"},
		&logical.Role{Name: "aws-mcp", Description: "aws mcp", ProviderPath: "mcp-aws/"},
		&logical.Role{Name: "skill-only", Description: "a recipe, no provider", Skill: "gh-repo-creator"},
		&logical.Role{Name: "plain", Description: "no discovery fields"},
	)

	out := listRolesFor(t, e)
	assert.Empty(t, out.Warnings)
	roles := rolesByName(out)

	assert.Equal(t, mcpRole{Name: "read-secret", Description: "read app secrets", Provider: "vault",
		Skill: "skill://vault/SKILL.md", URL: "/v1/team/vault/role/read-secret/gateway/"}, roles["read-secret"])
	assert.Equal(t, "skill://gh-repo-creator/SKILL.md", roles["repo-creator"].Skill)
	assert.Equal(t, "/v1/team/vault/role/repo-creator/gateway/", roles["repo-creator"].URL)
	assert.Equal(t, "/v1/team/aws/gateway", roles["s3-reader"].URL)
	assert.Equal(t, "skill://aws/SKILL.md", roles["s3-reader"].Skill)
	assert.Equal(t, "/v1/team/rds-prod/access/", roles["db-reader"].URL)
	assert.Equal(t, "mcp_aws", roles["aws-mcp"].Provider)
	assert.Equal(t, "skill://mcp-aws/SKILL.md", roles["aws-mcp"].Skill, "the default skill is the hyphenated type")
	assert.Equal(t, mcpRole{Name: "skill-only", Description: "a recipe, no provider",
		Skill: "skill://gh-repo-creator/SKILL.md"}, roles["skill-only"])
	assert.Equal(t, mcpRole{Name: "plain", Description: "no discovery fields"}, roles["plain"])
}

// Every way a granted role's discovery fields can fail to resolve leaves the
// role listed without the unresolved fields and explains why in a warning. A
// role granted only at a mount its provider does not admit through is not
// listed at all.
func TestListRoles_UnresolvedFieldsBecomeWarnings(t *testing.T) {
	e := setupDiscovery(t)
	ctx := e.ctx
	e.mountAuth("jwt-b/")
	mountDiscoveryProvider(t, e.c, ctx, "vault", "vault/", "auth/jwt/", "")
	mountDiscoveryProvider(t, e.c, ctx, "anthropic", "anthropic/", "auth/jwt/", "")
	mountDiscoveryProvider(t, e.c, ctx, "github", "github/", "", "")
	// The gateway resolves auto_auth_path verbatim and "auth/jwt" does not
	// reach the auth/jwt/ mount, so discovery must not vouch for a URL here.
	mountDiscoveryProvider(t, e.c, ctx, "slack", "slack/", "auth/jwt", "")
	seedTestSkill(t, e.c, rootCtx(), "vault")
	seedTestSkill(t, e.c, rootCtx(), "custom")

	e.grant("all", []string{"auth/jwt/"},
		&logical.Role{Name: "gone", ProviderPath: "vault-old/"},
		&logical.Role{Name: "no-default-skill", ProviderPath: "anthropic/"},
		&logical.Role{Name: "custom-on-skill-less-type", ProviderPath: "anthropic/", Skill: "custom"},
		&logical.Role{Name: "missing-skill", ProviderPath: "vault/", Skill: "nope"},
		&logical.Role{Name: "no-auto-auth", ProviderPath: "github/"},
		&logical.Role{Name: "slashless-auto-auth", ProviderPath: "slack/"},
	)
	e.grant("elsewhere", []string{"auth/jwt-b/"}, &logical.Role{Name: "wrong-auth", ProviderPath: "vault/"})

	out := listRolesFor(t, e)
	roles := rolesByName(out)
	warnings := strings.Join(out.Warnings, "\n")

	assert.Equal(t, mcpRole{Name: "gone"}, roles["gone"])
	assert.Contains(t, warnings, `role "gone": provider_path "vault-old/" is not a provider mount in this namespace`)

	assert.Equal(t, "/v1/team/anthropic/role/no-default-skill/gateway/", roles["no-default-skill"].URL)
	assert.Empty(t, roles["no-default-skill"].Skill, "anthropic ships no skill, and that is not a warning")
	assert.NotContains(t, warnings, "no-default-skill")

	assert.Equal(t, "skill://custom/SKILL.md", roles["custom-on-skill-less-type"].Skill,
		"an explicit skill applies whether or not the provider type ships one")
	assert.NotContains(t, warnings, "custom-on-skill-less-type")

	assert.Equal(t, "/v1/team/vault/role/missing-skill/gateway/", roles["missing-skill"].URL)
	assert.Empty(t, roles["missing-skill"].Skill, "a missing explicit skill does not fall back to the default")
	assert.Contains(t, warnings, `role "missing-skill": skill "nope" does not exist`)

	assert.Empty(t, roles["no-auto-auth"].URL)
	assert.Contains(t, warnings, `role "no-auto-auth": provider "github/" has no auto_auth_path`)

	assert.Empty(t, roles["slashless-auto-auth"].URL)
	assert.Contains(t, warnings, `role "slashless-auto-auth": provider "slack/": auto_auth_path "auth/jwt" names no auth mount`)
	assert.NotContains(t, warnings, "does not authenticate through")

	assert.NotContains(t, roles, "wrong-auth", "granted only where its provider does not admit")
	assert.NotContains(t, warnings, "wrong-auth")
	assert.NotContains(t, warnings, "jwt-b/")
}

// The URL carries the namespace the caller selected.
func TestListRoles_URLCarriesNamespace(t *testing.T) {
	e := newDiscEnv(t, "team-data/", "")
	e.mountAuth("jwt/")
	e.provider("vault", "vault/", "auth/jwt/")
	e.grant("readers", []string{"auth/jwt/"}, &logical.Role{Name: "read-secret", ProviderPath: "vault/"})

	srv := startMCPTestServer(t, e.c, nil)
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
