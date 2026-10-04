package dev

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
	return renderTourAs("claude", only)
}

func renderTourAs(name string, only int) string {
	var buf bytes.Buffer
	renderTour(&buf, scenariosResponse{Setup: playground.SetupCommands, Scenarios: playground.Scenarios()}, only, "http://127.0.0.1:8400", clients[name])
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
	// first, it would let the 300 through before the reader saw it refused.
	third := renderTourFor(3)
	refused := strings.Index(third, `Ask: "Withdraw 300."`)
	raise := strings.Index(third, "warden policy write -type mcp atm-tools")
	require.NotEqual(t, -1, refused)
	require.NotEqual(t, -1, raise)
	assert.Less(t, refused, raise, "the limit is raised after the 300 is refused")
	assert.Less(t, strings.Index(third, "Then: Raise the limit"), raise)
	again := strings.LastIndex(third, `Ask: "Withdraw 300."`)
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

// Commands paste as printed: a heredoc's delimiter must stand alone on its line,
// or the reader's shell waits for more input.
func TestRenderTour_CommandsPasteAsPrinted(t *testing.T) {
	all := renderTourFor(0)
	assert.Contains(t, all, "\nexport WARDEN_ADDR=http://127.0.0.1:8400\n")
	assert.Contains(t, all, "\nAGENT=$(warden dev jwt agent agent-1 -ttl 8h)\n")
	heredocs := 0
	for _, line := range strings.Split(all, "\n") {
		if strings.TrimSpace(line) == "EOF" {
			assert.Equal(t, "EOF", line, "an indented delimiter never ends the heredoc")
			heredocs++
		}
	}
	assert.Equal(t, 2, heredocs, "scenario 3's policy and scenario 9's spec")

	// Paste the block as a reader would, then a line after it: that line runs
	// only if the heredoc ended where the block does.
	third := renderTourFor(3)
	start := strings.Index(third, "warden policy write")
	require.NotEqual(t, -1, start)
	// The delimiter line, not the <<EOF that opens the heredoc.
	end := strings.Index(third[start:], "\nEOF\n")
	require.NotEqual(t, -1, end)
	block := third[start : start+end+len("\nEOF\n")]
	cmd := exec.Command("sh")
	cmd.Stdin = strings.NewReader("warden() { cat >/dev/null; }\n" + block + "echo pasted\n")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s", out)
	assert.Equal(t, "pasted\n", string(out), "the heredoc ended, and the next command ran")
}

func TestClaudeAdd(t *testing.T) {
	a := &playground.Attachment{Server: "bank", Path: "/v1/bank-me/role/assistant/gateway/", Headers: []playground.Header{
		{Name: "X-Warden-Agent-Token", Value: "$AGENT"},
		{Name: "Authorization", Value: "Bearer $ALICE"},
	}}
	assert.Equal(t,
		`claude mcp add --transport http bank "http://127.0.0.1:8400/v1/bank-me/role/assistant/gateway/" \`+"\n"+
			`  --header "X-Warden-Agent-Token: $AGENT" \`+"\n"+
			`  --header "Authorization: Bearer $ALICE"`,
		claudeAdd(a, "http://127.0.0.1:8400"))
}

func TestResolveClient(t *testing.T) {
	t.Cleanup(func() { scenariosClient = "" })

	t.Setenv("WARDEN_DEV_CLIENT", "")
	c, err := resolveClient()
	require.NoError(t, err)
	assert.Equal(t, "claude", c.name, "Claude Code by default")

	t.Setenv("WARDEN_DEV_CLIENT", "cursor")
	c, err = resolveClient()
	require.NoError(t, err)
	assert.Equal(t, "cursor", c.name)

	scenariosClient = "Codex"
	c, err = resolveClient()
	require.NoError(t, err)
	assert.Equal(t, "codex", c.name, "the flag wins over the environment, in any case")

	scenariosClient = "bogus"
	_, err = resolveClient()
	assert.True(t, errors.Is(err, helpers.ErrUsage))
	assert.ErrorContains(t, err, strings.Join(clientNames(), ", "))
}

// Every client gets its own commands and hints, and only Claude Code's name
// appears in the tour printed for it.
func TestRenderTour_Clients(t *testing.T) {
	for _, name := range clientNames() {
		t.Run(name, func(t *testing.T) {
			c := clients[name]
			all := renderTourAs(name, 0)
			if name != "claude" {
				assert.NotContains(t, all, "claude mcp")
				assert.NotContains(t, all, "Claude Code")
			}
			assert.Contains(t, all, "Then "+c.reconnect+".")
			assert.Contains(t, renderTourAs(name, 8), "Then restart your agent, so it inherits the exports: "+c.restart+".",
				"scenario 8's exports reach only an agent started after them")
			if c.launch != "" {
				assert.Contains(t, all, c.launch)
			}
			for _, line := range strings.Split(all, "\n") {
				if strings.TrimSpace(line) == "EOF" {
					assert.Equal(t, "EOF", line, "an indented delimiter never ends the heredoc")
				}
			}
		})
	}

	// A client that adds servers by command replaces the bank, as Claude Code does.
	gemini := renderTourAs("gemini", 4)
	assert.Less(t, strings.Index(gemini, "gemini mcp remove bank"), strings.Index(gemini, "gemini mcp add -t http bank"))
	assert.Contains(t, gemini, `-H "X-Warden-Agent-Token: $AGENT"`)
	assert.Contains(t, renderTourAs("gemini", 0), "mkdir -p $HOME/warden-playground && cd $HOME/warden-playground",
		"gemini mcp add writes .gemini/settings.json where it runs")

	// Only Claude Code's raw-result shortcut is known.
	assert.Contains(t, renderTourFor(1), "read access_token. In Claude Code, press ctrl+o.")
	assert.NotContains(t, renderTourAs("cursor", 1), "ctrl+o")
}

var (
	configWrite = regexp.MustCompile(`(?ms)^mkdir -p "\$HOME/warden-playground.*?^EOF$`)
	configPath  = regexp.MustCompile(`cat > "\$HOME/([^"]+)"`)
	tomlServer  = regexp.MustCompile(`^\[mcp_servers\.([a-z-]+)\]$`)
	tomlPair    = regexp.MustCompile(`"([^"]+)" = "([^"]*)"`)
)

// pasteConfig pastes the nth config write in out into a shell, as a reader
// would, and returns the servers the file it wrote attaches, with their
// headers.
func pasteConfig(t *testing.T, name, out string, nth int) map[string]map[string]string {
	t.Helper()
	blocks := configWrite.FindAllString(out, -1)
	require.Greater(t, len(blocks), nth, "config write %d", nth)
	home := t.TempDir()
	cmd := exec.Command("sh")
	cmd.Env = append(os.Environ(), "HOME="+home, "AGENT=jwt-agent-1", "ALICE=jwt-alice", "BOB=jwt-bob")
	cmd.Stdin = strings.NewReader("warden() { echo jwt-agent-2; }\n" + blocks[nth] + "\n")
	shOut, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s", shOut)
	raw, err := os.ReadFile(filepath.Join(home, configPath.FindStringSubmatch(blocks[nth])[1]))
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "$", "the shell filled in every value")

	servers := map[string]map[string]string{}
	if name == "codex" {
		current := ""
		for _, line := range strings.Split(string(raw), "\n") {
			if m := tomlServer.FindStringSubmatch(line); m != nil {
				current = m[1]
				servers[current] = map[string]string{}
			}
			if strings.HasPrefix(line, "http_headers = ") {
				for _, m := range tomlPair.FindAllStringSubmatch(line, -1) {
					servers[current][m[1]] = m[2]
				}
			}
		}
		return servers
	}
	var doc map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &doc), "%s", raw)
	key := map[string]string{"cursor": "mcpServers", "vscode": "servers", "opencode": "mcp"}[name]
	var entries map[string]struct {
		URL     string            `json:"url"`
		Headers map[string]string `json:"headers"`
	}
	require.NoError(t, json.Unmarshal(doc[key], &entries))
	for server, e := range entries {
		assert.True(t, strings.HasPrefix(e.URL, "http://127.0.0.1:8400/v1/"), e.URL)
		servers[server] = e.Headers
	}
	return servers
}

// A client with a config file gets the whole file at each change, and a
// scenario printed alone knows what the ones before it attached.
func TestRenderTour_FileClientsWriteValidConfig(t *testing.T) {
	agentOnly := map[string]string{"Authorization": "Bearer jwt-agent-1"}
	forAlice := map[string]string{"Authorization": "Bearer jwt-alice", "X-Warden-Agent-Token": "jwt-agent-1"}
	for _, name := range []string{"codex", "cursor", "opencode", "vscode"} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, map[string]map[string]string{"bank": agentOnly}, pasteConfig(t, name, renderTourAs(name, 1), 0))

			fourth := renderTourAs(name, 4)
			assert.Equal(t, map[string]map[string]string{"bank": forAlice}, pasteConfig(t, name, fourth, 0))
			assert.Equal(t, "Bearer jwt-bob", pasteConfig(t, name, fourth, 1)["bank"]["Authorization"], "as bob")
			assert.Equal(t, "jwt-agent-2", pasteConfig(t, name, fourth, 2)["bank"]["X-Warden-Agent-Token"],
				"the substitution runs as the file is written")

			assert.Equal(t, map[string]map[string]string{"bank": forAlice, "warden": agentOnly}, pasteConfig(t, name, renderTourAs(name, 7), 0),
				"discovery beside the bank scenario 5 attached")
			assert.Equal(t, map[string]map[string]string{"warden": agentOnly}, pasteConfig(t, name, renderTourAs(name, 8), 0),
				"the REST scenario detaches the bank")
			assert.Equal(t, map[string]map[string]string{"warden": agentOnly, "github": agentOnly}, pasteConfig(t, name, renderTourAs(name, 9), 0))

			// Scenarios that change nothing attached write nothing.
			for _, n := range []int{2, 6} {
				assert.Empty(t, configWrite.FindAllString(renderTourAs(name, n), -1), "scenario %d", n)
			}
		})
	}
}

// The generic client prints what to enter, with the shell's values filled in.
func TestRenderTour_Generic(t *testing.T) {
	first := renderTourAs("generic", 1)
	start := strings.Index(first, "cat <<EOF")
	require.NotEqual(t, -1, start)
	end := strings.Index(first[start:], "\nEOF\n")
	require.NotEqual(t, -1, end)
	cmd := exec.Command("sh")
	cmd.Env = append(os.Environ(), "AGENT=jwt-agent-1")
	cmd.Stdin = strings.NewReader(first[start : start+end+len("\nEOF\n")])
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s", out)
	assert.Contains(t, string(out), "  URL:    http://127.0.0.1:8400/v1/bank/role/atm/gateway/\n")
	assert.Contains(t, string(out), "  Header: Authorization: Bearer jwt-agent-1\n")

	assert.Contains(t, renderTourAs("generic", 8), `# Remove the MCP server "bank" from your client.`)
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
