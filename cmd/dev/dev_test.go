package dev

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/cmd/helpers"
	"github.com/stephnangue/warden/internal/playground"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newJWTCmd gives each test its own flag state.
func newJWTCmd(t *testing.T, flags map[string]string) *cobra.Command {
	t.Helper()
	jwtMayAct, jwtTTL, jwtClaims, jwtJSON = "", 0, "", ""
	cmd := &cobra.Command{}
	cmd.Flags().StringVar(&jwtMayAct, "may-act", "", "")
	cmd.Flags().DurationVar(&jwtTTL, "ttl", 0, "")
	cmd.Flags().StringVar(&jwtClaims, "claims", "", "")
	cmd.Flags().StringVar(&jwtJSON, "json", "", "")
	for k, v := range flags {
		require.NoError(t, cmd.Flags().Set(k, v))
	}
	return cmd
}

func TestJWTPayload_FromArguments(t *testing.T) {
	cmd := newJWTCmd(t, map[string]string{"may-act": "agent-1", "ttl": "2h", "claims": `{"team":"payments"}`})
	payload, err := jwtPayload(cmd, []string{"user", "alice"})
	require.NoError(t, err)
	assert.Equal(t, map[string]any{
		"kind": "user", "sub": "alice", "may_act": "agent-1", "ttl": "2h0m0s",
		"claims": map[string]any{"team": "payments"},
	}, payload)
}

func TestJWTPayload_FromJSON(t *testing.T) {
	cmd := newJWTCmd(t, map[string]string{"json": `{"kind":"user","sub":"alice","may_act":{"sub":"agent-1"},"ttl":"1h"}`})
	payload, err := jwtPayload(cmd, nil)
	require.NoError(t, err)
	assert.Equal(t, "agent-1", payload["may_act"], "the claim's own shape is accepted")
	assert.Equal(t, "1h", payload["ttl"])
}

func TestJWTPayload_Refuses(t *testing.T) {
	_, err := jwtPayload(newJWTCmd(t, nil), []string{"agent"})
	assert.True(t, errors.Is(err, helpers.ErrUsage), "a missing subject is a usage error")

	_, err = jwtPayload(newJWTCmd(t, map[string]string{"json": `{"kind":"agent","sub":"a"}`, "may-act": "x"}), nil)
	assert.True(t, errors.Is(err, helpers.ErrUsage), "-json cannot be mixed with flags")

	_, err = jwtPayload(newJWTCmd(t, map[string]string{"json": `{"kind":"agent","sub":"a"}`}), []string{"agent", "a"})
	assert.True(t, errors.Is(err, helpers.ErrUsage), "-json cannot be mixed with arguments")

	_, err = jwtPayload(newJWTCmd(t, map[string]string{"claims": `[1,2]`}), []string{"agent", "a"})
	assert.True(t, errors.Is(err, helpers.ErrInvalidInput), "-claims must be an object")
}

func TestDecodeClaims(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"agent-1","aud":"warden-agent"}`))
	assert.Equal(t, map[string]any{"sub": "agent-1", "aud": "warden-agent"}, decodeClaims("h."+payload+".s"))
	assert.Nil(t, decodeClaims("not-a-jwt"))
}

func renderTourFor(only int) string {
	var buf bytes.Buffer
	renderTour(&buf, scenariosResponse{Setup: playground.SetupCommands, Scenarios: playground.Scenarios()}, only, "http://127.0.0.1:8400")
	return buf.String()
}

func TestRenderTour(t *testing.T) {
	all := renderTourFor(0)
	assert.True(t, strings.HasPrefix(all, "Setup, once:"))
	assert.Contains(t, all, "export WARDEN_ADDR=http://127.0.0.1:8400")
	assert.Contains(t, all, "AGENT=$(warden dev jwt agent agent-1 -ttl 8h)")
	assert.Contains(t, all, `BOB=$(warden dev jwt user bob -may-act agent-1 -claims '{"tier": "premium"}' -ttl 8h)`)

	first := renderTourFor(1)
	assert.Contains(t, first, `claude mcp add --transport http bank "http://127.0.0.1:8400/v1/bank/role/atm/gateway/"`)
	assert.NotContains(t, first, "claude mcp remove", "nothing to replace on the first attachment")
	assert.NotContains(t, first, "Setup, once:")

	// The live edit comes after the questions it would otherwise change: run
	// first, it would let the 500 through before the reader saw it refused.
	third := renderTourFor(3)
	refused := strings.Index(third, `Ask: "Withdraw 500."`)
	raise := strings.Index(third, "warden policy write -type mcp atm-tools")
	require.NotEqual(t, -1, refused)
	require.NotEqual(t, -1, raise)
	assert.Less(t, refused, raise, "the limit is raised after the 500 is refused")
	assert.Less(t, strings.Index(third, "Then: Raise the limit"), raise)
	again := strings.LastIndex(third, `Ask: "Withdraw 500."`)
	assert.Less(t, raise, again, "and the same question is asked again")
	assert.Less(t, again, strings.Index(third, "What it shows:"))

	// One bank at a time: a later scenario replaces it, then asks to reconnect.
	fourth := renderTourFor(4)
	assert.Less(t, strings.Index(fourth, "claude mcp remove bank"), strings.Index(fourth, "claude mcp add"))
	assert.Contains(t, fourth, `--header "X-Warden-Agent-Token: $AGENT"`)
	assert.Contains(t, fourth, "Then reconnect")
	assert.Contains(t, fourth, "Optional: As bob")
	// Each variant that swaps the bank asks to reconnect too: a running agent
	// keeps the old headers, and would go on acting for alice.
	assert.Equal(t, 3, strings.Count(fourth, "Then reconnect"), "the scenario and both variants")
	bob := fourth[strings.Index(fourth, "Optional: As bob"):]
	assert.Less(t, strings.Index(bob, "Then reconnect"), strings.Index(bob, "Ask:"), "before the variant's question")

	eighth := renderTourFor(8)
	assert.Contains(t, eighth, "claude mcp remove bank")
	assert.NotContains(t, eighth, "claude mcp add", "the REST scenario attaches nothing new")

	// The playground set GitHub up; the reader brings the PAT, then connects.
	// GitHub is attached beside discovery, not in place of a bank.
	ninth := renderTourFor(9)
	add := strings.Index(ninth, `claude mcp add --transport http github "http://127.0.0.1:8400/v1/github-mcp/role/github/gateway/"`)
	require.NotEqual(t, -1, add)
	assert.Less(t, strings.Index(ninth, "warden cred spec create github-pat"), add)
	for _, bootstrapped := range []string{"provider enable", "cred source create", "policy write", "role/github <<EOF"} {
		assert.NotContains(t, ninth, bootstrapped, "the playground did this already")
	}
	assert.NotContains(t, ninth, "claude mcp remove")
	assert.Contains(t, ninth, "Then reconnect")
	assert.Contains(t, ninth, "read -rs GITHUB_PAT", "the PAT is read without echo")
}

// Only this command's -o flag asks for structured output; WARDEN_OUTPUT does
// not, so $(warden dev jwt ...) captures a bare token for everyone.
func TestStructuredOutputRequested(t *testing.T) {
	t.Cleanup(func() { helpers.SetOutputFormat("") })
	for flag, want := range map[string]bool{
		"": false, "table": false, "text": false, "json": true, "ndjson": true, "JSON": true,
	} {
		helpers.SetOutputFormat(flag)
		assert.Equal(t, want, structuredOutputRequested(), "-o %q", flag)
	}

	helpers.SetOutputFormat("")
	t.Setenv("WARDEN_OUTPUT", "json")
	assert.False(t, structuredOutputRequested(), "WARDEN_OUTPUT=json still prints the bare token")
}

func TestAuditQuery(t *testing.T) {
	assert.Equal(t, map[string][]string{"n": {"20"}}, auditQuery(20, "", "", "", ""), "unset filters are left out")
	assert.Equal(t, map[string][]string{
		"n": {"1"}, "principal": {"atm"}, "user": {"alice"}, "role": {"atm"}, "decision": {"deny"},
	}, auditQuery(1, "atm", "alice", "atm", "deny"), "filters with the same value are each sent")
}

// The role filter must not shadow the global -role flag, whose -r shorthand
// would then stop parsing.
func TestAuditCmd_RoleFilterDoesNotShadowTheGlobalFlag(t *testing.T) {
	assert.Nil(t, AuditCmd.Flags().Lookup("role"))
	assert.NotNil(t, AuditCmd.Flags().Lookup("role-name"))
}
