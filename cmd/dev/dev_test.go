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
	assert.Contains(t, all, "AGENT=$(warden dev jwt agent agent-1)")

	first := renderTourFor(1)
	assert.Contains(t, first, `claude mcp add --transport http bank "http://127.0.0.1:8400/v1/bank/role/atm/gateway/"`)
	assert.NotContains(t, first, "claude mcp remove", "nothing to replace on the first attachment")
	assert.NotContains(t, first, "Setup, once:")

	// One bank at a time: a later scenario replaces it, then asks to reconnect.
	fourth := renderTourFor(4)
	assert.Less(t, strings.Index(fourth, "claude mcp remove bank"), strings.Index(fourth, "claude mcp add"))
	assert.Contains(t, fourth, `--header "X-Warden-Agent-Token: $AGENT"`)
	assert.Contains(t, fourth, "Then reconnect")
	assert.Contains(t, fourth, "Optional: As bob")

	seventh := renderTourFor(7)
	assert.Contains(t, seventh, "claude mcp remove bank")
	assert.NotContains(t, seventh, "claude mcp add", "the REST scenario attaches nothing new")
}
