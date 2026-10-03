//go:build e2e

// Package playground walks the dev playground's seven scenarios end to end
// against a real `warden server -dev-playground`, the way a first-time user
// would, but with the go-sdk MCP client and plain HTTP in place of an agent.
// It needs no Hydra and no Docker dependencies: the playground brings its own
// identity provider and upstream. It fails when a scenario stops showing what
// `warden dev scenarios` says it shows.
package playground

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/e2e/helpers"
	"github.com/stephnangue/warden/internal/playground"
)

const rootToken = "root"

// env is a running playground.
type env struct {
	addr string // Warden, e.g. http://127.0.0.1:41234
}

// freeAddr returns a loopback address with a port free at the time of asking.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	return ln.Addr().String()
}

// startPlayground runs a playground server on free ports, so the suite never
// collides with a developer's dev server or the e2e cluster.
func startPlayground(t *testing.T) *env {
	t.Helper()
	listen := freeAddr(t)
	cmd := exec.Command(helpers.WardenBin(), "server", "-dev-playground",
		"-dev-root-token="+rootToken,
		"-dev-listen-address="+listen,
		"-dev-playground-as-addr="+freeAddr(t),
		"-dev-playground-bank-addr="+freeAddr(t),
	)
	var out syncBuffer
	cmd.Stdout, cmd.Stderr = &out, &out
	require.NoError(t, cmd.Start())
	// One Wait, started now, so a server that exits during startup is noticed
	// at once rather than after the whole deadline.
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()
	t.Cleanup(func() {
		_ = cmd.Process.Signal(os.Interrupt)
		select {
		case <-exited:
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			<-exited
		}
		if t.Failed() {
			t.Logf("server output:\n%s", out.String())
		}
	})

	e := &env{addr: "http://" + listen}
	deadline := time.After(60 * time.Second)
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		// Health answers once the listener is up, which happens after the
		// bootstrap and its self-check have passed.
		if resp, err := http.Get(e.addr + "/v1/sys/health"); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return e
			}
		}
		select {
		case <-exited:
			t.Fatalf("the playground server exited during startup:\n%s", out.String())
		case <-deadline:
			t.Fatalf("the playground server did not start within 60s:\n%s", out.String())
		case <-tick.C:
		}
	}
}

// syncBuffer is a bytes.Buffer the server's output goroutines and the test can
// share.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// cli runs the warden CLI against the playground and returns its stdout.
func (e *env) cli(t *testing.T, stdin string, args ...string) string {
	t.Helper()
	cmd := exec.Command(helpers.WardenBin(), args...)
	cmd.Env = append(os.Environ(), "WARDEN_ADDR="+e.addr, "WARDEN_TOKEN="+rootToken)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	require.NoError(t, cmd.Run(), "warden %s: %s", strings.Join(args, " "), stderr.String())
	return strings.TrimSpace(stdout.String())
}

// sh runs a command line the tour prints, in a shell, with the warden binary
// on the PATH, so heredocs and quoting are exercised as a reader runs them.
func (e *env) sh(t *testing.T, line string) string {
	t.Helper()
	cmd := exec.Command("sh", "-c", line)
	cmd.Env = append(os.Environ(),
		"PATH="+filepath.Dir(helpers.WardenBin())+string(os.PathListSeparator)+os.Getenv("PATH"),
		"WARDEN_ADDR="+e.addr, "WARDEN_TOKEN="+rootToken)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	require.NoError(t, cmd.Run(), "%s: %s", line, stderr.String())
	return strings.TrimSpace(stdout.String())
}

// rawCall POSTs one JSON-RPC message to an MCP gateway path, as a client that
// skips its SDK's checks would.
func (e *env) rawCall(t *testing.T, path, token, message string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, e.addr+path, strings.NewReader(message))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// headerTransport sets fixed headers on every request, as an attached MCP
// client does.
type headerTransport map[string]string

func (h headerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	for k, v := range h {
		r.Header.Set(k, v)
	}
	return http.DefaultTransport.RoundTrip(r)
}

// attach connects an MCP client to path with headers, like `claude mcp add`.
func (e *env) attach(t *testing.T, path string, headers map[string]string) (*mcp.ClientSession, error) {
	t.Helper()
	client := mcp.NewClient(&mcp.Implementation{Name: "playground-e2e", Version: "1"}, nil)
	session, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint:             e.addr + path,
		HTTPClient:           &http.Client{Transport: headerTransport(headers)},
		MaxRetries:           -1,
		DisableStandaloneSSE: true,
	}, nil)
	if err == nil {
		t.Cleanup(func() { session.Close() })
	}
	return session, err
}

// bankResult is a bank answer, from either face.
type bankResult struct {
	Result *struct {
		Account   string `json:"account"`
		Balance   int64  `json:"balance"`
		Withdrawn int64  `json:"withdrawn"`
		Closed    bool   `json:"closed"`
	} `json:"result"`
	Error       string         `json:"error"`
	AccessToken map[string]any `json:"access_token"`
}

func callTool(t *testing.T, s *mcp.ClientSession, name string, args map[string]any) (bankResult, error) {
	t.Helper()
	res, err := s.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		return bankResult{}, err
	}
	raw, err := json.Marshal(res.StructuredContent)
	require.NoError(t, err)
	var out bankResult
	require.NoError(t, json.Unmarshal(raw, &out))
	return out, nil
}

// callOnce attaches, calls one tool, and detaches. Warden answers a refused call
// with HTTP 403, which the go-sdk client takes as a transport failure and closes
// the session on, so each call that may be refused gets a session of its own.
func (e *env) callOnce(t *testing.T, path string, headers map[string]string, name string, args map[string]any) (bankResult, error) {
	t.Helper()
	s, err := e.attach(t, path, headers)
	if err != nil {
		return bankResult{}, err
	}
	defer s.Close()
	return callTool(t, s, name, args)
}

// isAgent reports whether sub is the playground workload identity of principal.
// The middle of a wid: subject is a per-run mount accessor, so it is never
// matched literally.
func isAgent(sub any, principal string) bool {
	s, _ := sub.(string)
	return strings.HasPrefix(s, "wid:") && strings.HasSuffix(s, ":"+principal)
}

func (e *env) rest(t *testing.T, token, method, route, contentType, body string) (int, bankResult) {
	t.Helper()
	req, err := http.NewRequest(method, e.addr+"/v1/bank-api/role/teller/gateway/accounts/me"+route, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	var out bankResult
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestPlayground(t *testing.T) {
	e := startPlayground(t)

	agent := e.cli(t, "", "dev", "jwt", "agent", "agent-1")
	alice := e.cli(t, "", "dev", "jwt", "user", "alice", "-may-act", "agent-1")
	bob := e.cli(t, "", "dev", "jwt", "user", "bob", "-may-act", "agent-1")
	require.Equal(t, 2, strings.Count(agent, "."), "warden dev jwt prints a bare JWT")
	atmHeaders := map[string]string{"Authorization": "Bearer " + agent}

	asURL, bankURL := "", ""

	t.Run("0 the tour prints commands for this server", func(t *testing.T) {
		// Captured output is not a terminal, so ask for the tour by name.
		tour := e.cli(t, "", "dev", "scenarios", "-o", "table")
		assert.Contains(t, tour, "export WARDEN_ADDR="+e.addr)
		assert.Contains(t, tour, `claude mcp add --transport http bank "`+e.addr+`/v1/bank/role/atm/gateway/"`)
		for _, s := range playground.Scenarios() {
			assert.Contains(t, tour, fmt.Sprintf("%d. %s", s.Number, s.Title))
		}
	})

	t.Run("1 the agent shows only its identity; Warden brings the credential", func(t *testing.T) {
		bank, err := e.attach(t, "/v1/bank/role/atm/gateway/", map[string]string{"Authorization": "Bearer " + agent})
		require.NoError(t, err)
		out, err := callTool(t, bank, "get_balance", nil)
		require.NoError(t, err)

		assert.Equal(t, "agent-1", out.Result.Account)
		tok := out.AccessToken
		assert.True(t, isAgent(tok["sub"], "agent-1"), "sub %v", tok["sub"])
		asURL, _ = tok["iss"].(string)
		aud, _ := tok["aud"].(string)
		bankURL = strings.TrimSuffix(aud, "/mcp")
		assert.True(t, strings.HasPrefix(asURL, "https://localhost:"), "issued by the bank's authorization server")
		assert.True(t, strings.HasSuffix(aud, "/mcp"), "for the bank's MCP face")
		assert.Equal(t, "warden", tok["client_id"])
		assert.InDelta(t, 300, tok["exp"].(float64)-tok["iat"].(float64), 1, "five minutes")

		// Keyless: Warden proves itself with its own assertion, and the source
		// stores nothing.
		var source struct {
			Type          string         `json:"type"`
			Config        map[string]any `json:"config"`
			StoredSecrets []string       `json:"stored_secrets"`
		}
		require.NoError(t, json.Unmarshal([]byte(e.cli(t, "", "cred", "source", "read", "bank-as", "-o", "json")), &source))
		assert.Equal(t, "token_exchange", source.Type)
		assert.Equal(t, "none", source.Config["client_auth"])
		assert.Empty(t, source.StoredSecrets, "no secret is stored anywhere")
	})

	t.Run("2 policy decides which tools", func(t *testing.T) {
		bank, err := e.attach(t, "/v1/bank/role/atm/gateway/", map[string]string{"Authorization": "Bearer " + agent})
		require.NoError(t, err)
		tools, err := bank.ListTools(context.Background(), nil)
		require.NoError(t, err)
		var names []string
		for _, tool := range tools.Tools {
			names = append(names, tool.Name)
		}
		assert.ElementsMatch(t, []string{"get_balance", "withdraw", "deposit"}, names, "close_account is hidden")

		_, err = e.callOnce(t, "/v1/bank/role/atm/gateway/", atmHeaders, "close_account", nil)
		assert.Error(t, err, "a direct call to the hidden tool is refused")

		// Relabelling the call must not slip it past the tool rules: Warden
		// refuses it on policy, before the bank (which would answer 415) sees it.
		call := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"close_account","arguments":{}}}`
		for _, contentType := range []string{"text/plain", ""} {
			req, err := http.NewRequest(http.MethodPost, e.addr+"/v1/bank/role/atm/gateway/", strings.NewReader(call))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+agent)
			req.Header.Set("Accept", "application/json, text/event-stream")
			if contentType != "" {
				req.Header.Set("Content-Type", contentType)
			}
			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			assert.Equal(t, http.StatusForbidden, resp.StatusCode, "Content-Type %q: %s", contentType, body)
			assert.Contains(t, string(body), "close_account", "refused by the tool rule, Content-Type %q", contentType)
		}
	})

	t.Run("3 policy decides which arguments", func(t *testing.T) {
		out, err := e.callOnce(t, "/v1/bank/role/atm/gateway/", atmHeaders, "withdraw", map[string]any{"amount": 50})
		require.NoError(t, err)
		assert.Equal(t, int64(50), out.Result.Withdrawn)
		_, err = e.callOnce(t, "/v1/bank/role/atm/gateway/", atmHeaders, "withdraw", map[string]any{"amount": 500})
		assert.Error(t, err, "500 is over the limit")

		// The limit judges withdraw only, and never errors on a call without an amount.
		_, err = e.callOnce(t, "/v1/bank/role/atm/gateway/", atmHeaders, "get_balance", nil)
		assert.NoError(t, err)
		_, err = e.callOnce(t, "/v1/bank/role/atm/gateway/", atmHeaders, "deposit", map[string]any{"amount": 500})
		assert.NoError(t, err)

		// A withdrawal whose amount Warden cannot read is refused by the
		// condition, before the bank's own input check would see it.
		for _, amount := range []string{`null`, `[500]`, `"500"`} {
			status, body := e.rawCall(t, "/v1/bank/role/atm/gateway/", agent,
				`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"withdraw","arguments":{"amount":`+amount+`}}}`)
			assert.Equal(t, http.StatusForbidden, status, "amount %s: %s", amount, body)
		}

		// Raise the limit live, with the command the scenario prints, run by a
		// shell as the reader would.
		e.sh(t, playground.Scenarios()[2].Commands[0])
		out, err = e.callOnce(t, "/v1/bank/role/atm/gateway/", atmHeaders, "withdraw", map[string]any{"amount": 500})
		require.NoError(t, err, "the next call follows the new limit")
		assert.Equal(t, int64(500), out.Result.Withdrawn)
	})

	t.Run("4 the agent acts for a person", func(t *testing.T) {
		asAlice, err := e.attach(t, "/v1/bank-me/role/assistant/gateway/", map[string]string{
			"X-Warden-Agent-Token": agent, "Authorization": "Bearer " + alice,
		})
		require.NoError(t, err)
		out, err := callTool(t, asAlice, "withdraw", map[string]any{"amount": 50})
		require.NoError(t, err)
		assert.Equal(t, "alice", out.Result.Account, "alice's account, not the agent's")
		assert.Equal(t, int64(950), out.Result.Balance)
		assert.Equal(t, "alice", out.AccessToken["sub"])
		act, _ := out.AccessToken["act"].(map[string]any)
		assert.True(t, isAgent(act["sub"], "agent-1"), "the agent in act: %v", act)

		asBob, err := e.attach(t, "/v1/bank-me/role/assistant/gateway/", map[string]string{
			"X-Warden-Agent-Token": agent, "Authorization": "Bearer " + bob,
		})
		require.NoError(t, err)
		out, err = callTool(t, asBob, "get_balance", nil)
		require.NoError(t, err)
		assert.Equal(t, "bob", out.Result.Account)
		assert.Equal(t, int64(1000), out.Result.Balance)

		agent2 := e.cli(t, "", "dev", "jwt", "agent", "agent-2")
		_, err = e.attach(t, "/v1/bank-me/role/assistant/gateway/", map[string]string{
			"X-Warden-Agent-Token": agent2, "Authorization": "Bearer " + alice,
		})
		assert.Error(t, err, "alice's may_act names agent-1, so agent-2 is refused, initialize included")
	})

	t.Run("5 every call is audited", func(t *testing.T) {
		var denies []map[string]any
		require.NoError(t, json.Unmarshal([]byte(e.cli(t, "", "dev", "audit", "-decision", "deny", "-limit", "50", "-o", "json")), &denies))
		reasons := map[string]bool{}
		for _, d := range denies {
			reasons[fmt.Sprintf("%v %v", d["role"], d["agent"])] = true
		}
		assert.True(t, reasons["atm agent-1"], "the refused withdrawal and hidden tool: %v", reasons)
		assert.True(t, reasons["assistant agent-2"], "agent-2 acting for alice: %v", reasons)

		var forAlice []map[string]any
		require.NoError(t, json.Unmarshal([]byte(e.cli(t, "", "dev", "audit", "-user", "alice", "-o", "json")), &forAlice))
		require.NotEmpty(t, forAlice)
		for _, entry := range forAlice {
			assert.Equal(t, "alice", entry["user"])
			assert.Equal(t, "assistant", entry["role"])
		}
	})

	t.Run("6 the agent finds its roles by itself", func(t *testing.T) {
		discovery, err := e.attach(t, "/v1/sys/mcp", map[string]string{"Authorization": "Bearer " + agent})
		require.NoError(t, err)
		res, err := discovery.CallTool(context.Background(), &mcp.CallToolParams{Name: "list_roles"})
		require.NoError(t, err)
		raw, _ := json.Marshal(res.StructuredContent)
		var listed struct {
			Roles []struct {
				Name, Provider, Skill, URL string
			} `json:"roles"`
			Warnings []string `json:"warnings"`
		}
		require.NoError(t, json.Unmarshal(raw, &listed))
		assert.Empty(t, listed.Warnings)
		got := map[string][3]string{}
		for _, r := range listed.Roles {
			got[r.Name] = [3]string{r.Provider, r.Skill, r.URL}
		}
		assert.Equal(t, map[string][3]string{
			"atm":       {"mcp", "skill://mcp/SKILL.md", "/v1/bank/role/atm/gateway/"},
			"assistant": {"mcp", "skill://mcp/SKILL.md", "/v1/bank-me/role/assistant/gateway/"},
			"teller":    {"rest", "skill://teller/SKILL.md", "/v1/bank-api/role/teller/gateway/"},
		}, got)

		for _, uri := range []string{"skill://teller/SKILL.md", "skill://rest/SKILL.md", "skill://mcp/SKILL.md"} {
			res, err := discovery.CallTool(context.Background(), &mcp.CallToolParams{Name: "read_skill", Arguments: map[string]any{"uri": uri}})
			require.NoError(t, err, uri)
			assert.False(t, res.IsError, "%s is readable", uri)
		}

		// A skill that exists, but that no role this identity can assume names,
		// reads exactly as one that does not exist.
		e.cli(t, "", "skill", "create", "vault-runbook", "-json",
			`{"description": "The operators' runbook.", "category": "custom", "body": "# Runbook\n\nFor operators only."}`)
		for _, uri := range []string{"skill://vault-runbook/SKILL.md", "skill://no-such-skill/SKILL.md"} {
			res, err := discovery.CallTool(context.Background(), &mcp.CallToolParams{Name: "read_skill", Arguments: map[string]any{"uri": uri}})
			require.NoError(t, err, "a refused read is a tool error, and the session stays up: %s", uri)
			require.True(t, res.IsError, uri)
			require.NotEmpty(t, res.Content, uri)
			text, _ := res.Content[0].(*mcp.TextContent)
			require.NotNil(t, text, uri)
			assert.Contains(t, text.Text, "not found", uri)
		}
	})

	t.Run("7 the same bank, as a plain HTTP API", func(t *testing.T) {
		status, before := e.rest(t, agent, http.MethodGet, "", "", "")
		require.Equal(t, http.StatusOK, status)
		assert.True(t, isAgent(before.AccessToken["sub"], "agent-1"))
		assert.Equal(t, bankURL+"/api", before.AccessToken["aud"], "a token for the REST face")
		assert.Equal(t, asURL, before.AccessToken["iss"])

		status, out := e.rest(t, agent, http.MethodPost, "/deposit", "application/json", `{"amount": 30}`)
		require.Equal(t, http.StatusOK, status)
		assert.Equal(t, before.Result.Balance+30, out.Result.Balance)

		status, _ = e.rest(t, agent, http.MethodPost, "/withdraw", "application/json", `{"amount": 500}`)
		assert.Equal(t, http.StatusForbidden, status, "the body condition refuses 500")
		status, _ = e.rest(t, agent, http.MethodPost, "/withdraw", "text/plain", `{"amount": 500}`)
		assert.Equal(t, http.StatusForbidden, status, "an unread body fails closed")
		status, _ = e.rest(t, agent, http.MethodPost, "/withdraw", "Application/JSON", `{"amount": 500}`)
		assert.Equal(t, http.StatusForbidden, status, "a relabelled JSON body is still read")
		status, out = e.rest(t, agent, http.MethodPost, "/withdraw", "application/json", `{"amount": 50}`)
		require.Equal(t, http.StatusOK, status)

		bank, err := e.attach(t, "/v1/bank/role/atm/gateway/", map[string]string{"Authorization": "Bearer " + agent})
		require.NoError(t, err)
		viaMCP, err := callTool(t, bank, "get_balance", nil)
		require.NoError(t, err)
		assert.Equal(t, out.Result.Balance, viaMCP.Result.Balance, "one account behind both faces")
	})
}
