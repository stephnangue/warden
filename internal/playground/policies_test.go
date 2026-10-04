// This file is an external test package on purpose: core imports the
// playground for its dev endpoints, so only a test outside the package can
// import core back.
package playground_test

import (
	"strings"
	"testing"

	"github.com/stephnangue/warden/core"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/internal/playground"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every policy the bootstrap writes, and the one scenario 3 has the reader
// write, parses with Warden's own parsers, which compile and type-check the
// conditions: a typo would otherwise surface only when the playground boots,
// or when a reader runs the scenario.
func TestPoliciesParse(t *testing.T) {
	steps := playground.Bootstrap(playground.Settings{
		WardenIssuer: "http://127.0.0.1:8400",
		ASURL:        "https://localhost:8410",
		BankURL:      "https://localhost:8420",
		AuditPath:    "/tmp/playground-audit.log",
	})
	parsed := 0
	for _, s := range steps {
		policy, ok := s.Data["policy"].(string)
		if !ok {
			continue
		}
		var err error
		switch {
		case strings.HasPrefix(s.Path, "sys/policies/cbp/"):
			_, err = core.ParseCBPPolicy(namespace.RootNamespace, policy)
		case strings.HasPrefix(s.Path, "sys/policies/mcp/"):
			_, err = core.ParseMCPPolicy(namespace.RootNamespace, policy)
		default:
			t.Fatalf("%s carries a policy of no known type", s.Path)
		}
		assert.NoError(t, err, s.Path)
		parsed++
	}
	assert.Equal(t, 5, parsed, "every policy the bootstrap writes")

	cmd := playground.Scenarios()[2].Commands[0]
	_, rest, ok := strings.Cut(cmd, "<<EOF\n")
	require.True(t, ok, "scenario 3 writes its policy from a heredoc")
	policy, ok := strings.CutSuffix(rest, "EOF")
	require.True(t, ok, "the heredoc is terminated")
	_, err := core.ParseMCPPolicy(namespace.RootNamespace, policy)
	assert.NoError(t, err, "scenario 3's live limit")

	// The policies the last scenario has the reader write for GitHub.
	_, err = core.ParseCBPPolicy(namespace.RootNamespace, playground.GitHubAccessPolicy)
	assert.NoError(t, err, "github-access")
	_, err = core.ParseMCPPolicy(namespace.RootNamespace, playground.GitHubReadPolicy)
	assert.NoError(t, err, "github-read")
}
