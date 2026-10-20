package logical

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidRoleName(t *testing.T) {
	for _, name := range []string{"a", "deploy", "deploy-prod", "deploy.v2", "x_1", "A9", "_x"} {
		assert.True(t, ValidRoleName(name), name)
	}
	for _, name := range []string{"", "-a", "a-", ".a", "a.", "a/b", "a b", "a:b", "é", "a\n"} {
		assert.False(t, ValidRoleName(name), "%q", name)
	}
}

func TestValidateAssignablePolicies(t *testing.T) {
	assert.NoError(t, ValidateAssignablePolicies(nil))
	assert.NoError(t, ValidateAssignablePolicies([]string{"deploy", "default"}))

	err := ValidateAssignablePolicies([]string{"deploy", "root"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"root"`)

	orig := nonAssignablePolicies
	nonAssignablePolicies = []string{"internal-only"}
	t.Cleanup(func() { nonAssignablePolicies = orig })

	assert.True(t, IsNonAssignablePolicy("internal-only"))
	assert.False(t, IsNonAssignablePolicy("root"), "root is refused separately")
	err = ValidateAssignablePolicies([]string{"deploy", "internal-only"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"internal-only"`)
}

func TestRoleHash(t *testing.T) {
	base := func() *Role {
		return &Role{
			Name:         "deploy",
			Description:  "d",
			Policies:     []string{"a", "b"},
			CredSpecName: "spec",
			Skill:        "aws",
			ProviderPath: "aws/",
			Metadata:     map[string]string{"team": "platform", "env": "prod"},
		}
	}
	h := base().Hash()
	assert.Len(t, h, 64)

	stamped := base()
	stamped.CreatedAt = time.Now()
	stamped.UpdatedAt = time.Now()
	assert.Equal(t, h, stamped.Hash(), "timestamps are not content")

	for name, mutate := range map[string]func(r *Role){
		"name":          func(r *Role) { r.Name = "other" },
		"description":   func(r *Role) { r.Description = "other" },
		"policies":      func(r *Role) { r.Policies = []string{"a"} },
		"cred spec":     func(r *Role) { r.CredSpecName = "other" },
		"skill":         func(r *Role) { r.Skill = "vault" },
		"provider path": func(r *Role) { r.ProviderPath = "vault/" },
		"metadata":      func(r *Role) { r.Metadata["env"] = "dev" },
		"metadata key":  func(r *Role) { r.Metadata["extra"] = "" },
	} {
		r := base()
		mutate(r)
		assert.NotEqual(t, h, r.Hash(), name)
	}

	// Field boundaries are unambiguous.
	a := &Role{Name: "x", Policies: []string{"ab"}}
	b := &Role{Name: "x", Policies: []string{"a", "b"}}
	assert.NotEqual(t, a.Hash(), b.Hash())
	c := &Role{Name: "x", Description: "a", CredSpecName: "b"}
	d := &Role{Name: "x", Description: "ab"}
	assert.NotEqual(t, c.Hash(), d.Hash())
}

func TestRoleClone(t *testing.T) {
	assert.Nil(t, (*Role)(nil).Clone())

	r := &Role{Name: "deploy", Policies: []string{"a"}, Metadata: map[string]string{"k": "v"}}
	c := r.Clone()
	require.Equal(t, r, c)
	c.Policies[0] = "changed"
	c.Metadata["k"] = "changed"
	assert.Equal(t, []string{"a"}, r.Policies)
	assert.Equal(t, "v", r.Metadata["k"])
}
