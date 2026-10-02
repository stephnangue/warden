package helper

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateDiscoveryFields(t *testing.T) {
	ok := []struct {
		skill, path, want string
	}{
		{"", "", ""},
		{"vault", "", ""},
		{"", "vault", "vault/"},
		{"", "vault/", "vault/"},
		{"gh-repo-creator", "team/github", "team/github/"},
	}
	for _, tc := range ok {
		got, err := ValidateDiscoveryFields(tc.skill, tc.path)
		require.NoError(t, err, "%q %q", tc.skill, tc.path)
		assert.Equal(t, tc.want, got)
	}

	bad := []struct {
		skill, path, wantSub string
	}{
		{"Gh_Repo", "", "invalid skill"},
		{"mcp_aws", "", "invalid skill"},
		{"", "/vault", "no leading"},
		{"", "a//b", "segment"},
		{"", "a/../b", "segment"},
		{"", "./vault", "segment"},
		{"", strings.Repeat("a", 257), "exceeds"},
	}
	for _, tc := range bad {
		_, err := ValidateDiscoveryFields(tc.skill, tc.path)
		require.Error(t, err, "%q %q", tc.skill, tc.path)
		assert.Contains(t, err.Error(), tc.wantSub)
	}
}
