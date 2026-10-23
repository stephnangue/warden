package core

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/logical"
)

// testGrant describes one role grant for grantRole: the role a credential may
// run under, what the role carries, and which admissions are granted it.
type testGrant struct {
	// Role is the namespace role granted. It is created when the namespace has
	// none by that name; an existing role is left as it is.
	Role string
	// Policies and Spec are the created role's policies and credential spec.
	Policies []string
	Spec     string
	// Mount is the admitting auth mount, namespace-relative ("auth/jwt/").
	Mount string
	// Rule holds selectors beyond the mount, as a group rule writes them
	// (fact name to values, exact or glob); nil grants the role to every
	// credential the mount admits.
	Rule map[string][]string
}

// grantRole makes "this credential is granted role R" true in ctx's namespace
// in one call: it creates the role when missing and a virtual group listing it
// whose one rule pins g.Mount plus g.Rule. The group is named after the role
// and mount, so granting the same role through another mount adds another
// group. It returns the group's name, the label a grant records as
// "group:<name>".
func grantRole(t testing.TB, c *Core, ctx context.Context, g testGrant) string {
	t.Helper()
	require.NotEmpty(t, g.Role)
	require.True(t, strings.HasPrefix(g.Mount, "auth/") && strings.HasSuffix(g.Mount, "/"),
		"Mount is namespace-relative: auth/<path>/, got %q", g.Mount)

	if existing, _, err := c.roleStore.Get(ctx, g.Role); err != nil || existing == nil {
		_, err := c.roleStore.Create(ctx, &logical.Role{Name: g.Role, Policies: g.Policies, CredSpecName: g.Spec})
		require.NoError(t, err)
	}

	rule := logical.GroupRule{"mount": {g.Mount}}
	for name, values := range g.Rule {
		rule[name] = values
	}
	name := "grant-" + g.Role + "-" + strings.ReplaceAll(strings.Trim(g.Mount, "/"), "/", "-")
	_, err := c.identityStore.CreateGroup(ctx, &logical.Group{
		Name:  name,
		Type:  logical.GroupTypeVirtual,
		Roles: []string{g.Role},
		Rules: []logical.GroupRule{rule},
	})
	require.NoError(t, err)
	return name
}
