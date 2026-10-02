package logical

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidSkillName(t *testing.T) {
	cases := []struct {
		name string
		ok   bool
	}{
		{"a", true},
		{"vault", true},
		{"mcp-aws", true},
		{"gh-repo-creator", true},
		{"v2", true},
		{strings.Repeat("a", 64), true},
		{strings.Repeat("a", 65), false},
		{"", false},
		{"mcp_aws", false},
		{"Vault", false},
		{"-vault", false},
		{"vault-", false},
		{"pdf--processing", false},
		{"a b", false},
		{"a.b", false},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.ok, ValidSkillName(tc.name), "name %q", tc.name)
	}
}

func TestSkillNameForProvider(t *testing.T) {
	assert.Equal(t, "vault", SkillNameForProvider("vault"))
	assert.Equal(t, "mcp-aws", SkillNameForProvider("mcp_aws"))
	assert.Equal(t, "ansible-tower", SkillNameForProvider("ansible_tower"))
	for _, typ := range []string{"vault", "mcp_aws", "ansible_tower"} {
		assert.True(t, ValidSkillName(SkillNameForProvider(typ)), typ)
	}
}
