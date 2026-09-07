package drivers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The tests below exercise the shared claim-templating mechanism through
// resolveSecretPath, the thin alias the KV read uses. They moved here with the
// mechanism itself; what they cover is the rule set, not that one caller.

// TestResolveSecretPath covers per-user secret_path templating and its fail-closed
// sanitization (the security boundary that keeps one user from reading another's
// secret or escaping the intended path).
func TestResolveSecretPath(t *testing.T) {
	claims := map[string]string{"username": "alice", "email": "alice@example.com", "dept": "eng-team"}
	agentClaims := map[string]string{"sub": "build-runner", "team": "platform"}

	tests := []struct {
		name    string
		path    string
		claims  map[string]string
		agent   map[string]string
		want    string
		wantErr string
	}{
		{"no template returned verbatim", "slack/refresh_token", claims, agentClaims, "slack/refresh_token", ""},
		{"no template needs no claims", "slack/refresh_token", nil, agentClaims, "slack/refresh_token", ""},
		{"single substitution", "slack/{{user.username}}/refresh_token", claims, agentClaims, "slack/alice/refresh_token", ""},
		{"multiple tokens resolved", "{{user.username}}/{{user.dept}}", claims, agentClaims, "alice/eng-team", ""},
		{"email value allowed", "kv/{{user.email}}", claims, agentClaims, "kv/alice@example.com", ""},
		{"hyphen value allowed", "kv/{{user.dept}}", claims, agentClaims, "kv/eng-team", ""},
		{"literal dots within a segment allowed", "kv/{{user.username}}", map[string]string{"username": "a..b"}, agentClaims, "kv/a..b", ""},
		// Both are spec/config mismatches, not missing-user cases: claims are
		// projected only when the spec asks for them, and core rejects a
		// user-less request before the driver runs. Neither is fixed by
		// authenticating, so neither may carry a 401 challenge.
		{"absent claim fails closed", "slack/{{user.missing}}/x", claims, agentClaims, "", "absent"},
		{"nil claims with template fails closed", "slack/{{user.username}}/x", nil, agentClaims, "", "absent"},
		{"slash in value rejected", "kv/{{user.username}}", map[string]string{"username": "a/b"}, agentClaims, "", "allow-list"},
		{"curly brace in value rejected", "kv/{{user.username}}", map[string]string{"username": "a{b"}, agentClaims, "", "allow-list"},
		{"empty value rejected", "kv/{{user.username}}", map[string]string{"username": ""}, agentClaims, "", "allow-list"},
		// The security boundary: values that compose a "." or ".." segment which the
		// Vault client's path.Clean would resolve into a shared/parent path.
		{"dot value collapses a segment", "slack/{{user.username}}/rt", map[string]string{"username": "."}, agentClaims, "", "traversal"},
		{"dotdot value traverses", "slack/{{user.username}}/rt", map[string]string{"username": ".."}, agentClaims, "", "traversal"},
		{"adjacent tokens compose dotdot", "slack/{{user.a}}{{user.b}}/rt", map[string]string{"a": ".", "b": "."}, agentClaims, "", "traversal"},
		{"unresolved fragment fails closed", "slack/{{user.username}/rt", map[string]string{"username": "alice"}, agentClaims, "", "unresolved"},

		// The agent namespace. Same rules and same failure modes — only the map a
		// value is looked up in differs.
		{"agent sub substitution", "agents/{{agent.sub}}/key", claims, agentClaims, "agents/build-runner/key", ""},
		{"agent metadata substitution", "teams/{{agent.team}}/key", claims, agentClaims, "teams/platform/key", ""},
		{"both namespaces compose", "teams/{{agent.team}}/users/{{user.username}}", claims, agentClaims, "teams/platform/users/alice", ""},
		{"absent agent claim fails closed", "agents/{{agent.missing}}/k", claims, agentClaims, "", "absent"},
		{"nil agent claims with template fails closed", "agents/{{agent.sub}}/k", claims, nil, "", "absent"},
		{"slash in agent value rejected", "kv/{{agent.team}}", claims, map[string]string{"team": "a/b"}, "", "allow-list"},
		{"empty agent value rejected", "kv/{{agent.team}}", claims, map[string]string{"team": ""}, "", "allow-list"},
		{"agent dotdot value traverses", "kv/{{agent.team}}/x", claims, map[string]string{"team": ".."}, "", "traversal"},
		{"agent and user values compose dotdot", "kv/{{agent.team}}{{user.a}}/x", map[string]string{"a": "."}, map[string]string{"team": "."}, "", "traversal"},
		{"unresolved agent fragment fails closed", "agents/{{agent.sub}/k", claims, agentClaims, "", "unresolved"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveSecretPath(tt.path, tt.claims, tt.agent)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestVaultDriver_OAuth2_PerUserCredentialName proves the oauth2 mint method templates

// The absent-claim error has to name the config key that fixes it, and the two
// namespaces are fixed by different keys — an operator who reads "absent" without
// being told where to list it has to guess.
func TestResolveSecretPath_AbsentClaimNamesItsOwnConfigKey(t *testing.T) {
	_, err := resolveSecretPath("kv/{{user.missing}}", map[string]string{"sub": "u"}, map[string]string{"sub": "a"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "assertion_user_claims")

	_, err = resolveSecretPath("kv/{{agent.missing}}", map[string]string{"sub": "u"}, map[string]string{"sub": "a"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "assertion_metadata_claims")
	assert.NotContains(t, err.Error(), "assertion_user_claims",
		"the agent's guidance must not point at the user's config key")
}

// The guidance has to match which of the three ways it failed, or it sends the
// operator to a config change that cannot help.
func TestResolveSecretPath_AgentGuidanceMatchesTheFailure(t *testing.T) {
	t.Run("nothing projected blames the subject source", func(t *testing.T) {
		_, err := resolveSecretPath("kv/{{agent.sub}}", nil, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "subject_token_source")
		assert.NotContains(t, err.Error(), "list it in assertion_metadata_claims",
			"sub needs no allow-list entry, so telling an operator to add one is a dead end")
	})
	t.Run("a missing metadata claim blames the list and the login", func(t *testing.T) {
		_, err := resolveSecretPath("kv/{{agent.team}}", nil, map[string]string{"sub": "a"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "assertion_metadata_claims")
		assert.Contains(t, err.Error(), "login",
			"listing the claim is necessary but not sufficient — an absent one is skipped, not rejected")
	})
}

// A path with no template must come back byte-identical whatever the claim maps
// hold — the guarantee that adding this feature changed nothing for specs that do
// not use it.
func TestResolveSecretPath_UntemplatedIsByteIdentical(t *testing.T) {
	const raw = "kv/data/service/config"
	for _, maps := range []struct {
		name        string
		user, agent map[string]string
	}{
		{"both nil", nil, nil},
		{"both populated", map[string]string{"sub": "u"}, map[string]string{"sub": "a"}},
	} {
		t.Run(maps.name, func(t *testing.T) {
			got, err := resolveSecretPath(raw, maps.user, maps.agent)
			require.NoError(t, err)
			assert.Equal(t, raw, got)
		})
	}
}