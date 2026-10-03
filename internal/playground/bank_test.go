package playground

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type bankFixture struct {
	bank   *Bank
	server *httptest.Server
	idp    *IdP
}

func newBankFixture(t *testing.T) *bankFixture {
	t.Helper()
	idp, err := NewIdP("https://localhost:8410")
	require.NoError(t, err)
	srv := httptest.NewUnstartedServer(nil)
	bank, err := NewBank("http://"+srv.Listener.Addr().String(), idp.Issuer(), idp.PublicKey())
	require.NoError(t, err)
	srv.Config.Handler = bank.Handler()
	srv.Start()
	t.Cleanup(srv.Close)
	return &bankFixture{bank: bank, server: srv, idp: idp}
}

// token is a bank token as the authorization server would issue it.
func (f *bankFixture) token(t *testing.T, audience string, claims map[string]any) string {
	t.Helper()
	claims["aud"] = audience
	token, err := f.idp.sign(claims, time.Minute)
	require.NoError(t, err)
	return token
}

func (f *bankFixture) rest(t *testing.T, method, route, token, contentType, body string) (int, RouteResult) {
	t.Helper()
	req, err := http.NewRequest(method, f.server.URL+BankAPIPath+route, strings.NewReader(body))
	require.NoError(t, err)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	var out RouteResult
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestBank_REST(t *testing.T) {
	f := newBankFixture(t)
	alice := f.token(t, f.bank.APIURL(), map[string]any{"sub": "alice", "scope": "bank"})

	status, out := f.rest(t, http.MethodGet, "/accounts/me", alice, "", "")
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, "alice", out.Result.Account)
	assert.Equal(t, OpeningBalance, out.Result.Balance)
	assert.Equal(t, "alice", out.AccessToken["sub"], "the decoded token is echoed")
	assert.Equal(t, f.bank.APIURL(), out.AccessToken["aud"])

	status, out = f.rest(t, http.MethodPost, "/accounts/me/deposit", alice, "application/json", `{"amount": 30}`)
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, int64(1030), out.Result.Balance)
	assert.Equal(t, int64(30), out.Result.Deposited)

	status, out = f.rest(t, http.MethodPost, "/accounts/me/withdraw", alice, "application/json; charset=utf-8", `{"amount": 50}`)
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, int64(980), out.Result.Balance)

	t.Run("an overdraft is the bank's own refusal", func(t *testing.T) {
		status, out := f.rest(t, http.MethodPost, "/accounts/me/withdraw", alice, "application/json", `{"amount": 5000}`)
		assert.Equal(t, http.StatusConflict, status)
		assert.Equal(t, "insufficient funds", out.Error)
		assert.Equal(t, int64(980), out.Result.Balance)
		assert.NotEmpty(t, out.AccessToken, "a refused call still shows the token")
	})

	t.Run("bodies must be JSON with a whole amount", func(t *testing.T) {
		status, _ := f.rest(t, http.MethodPost, "/accounts/me/deposit", alice, "text/plain", `{"amount": 30}`)
		assert.Equal(t, http.StatusUnsupportedMediaType, status)
		status, _ = f.rest(t, http.MethodPost, "/accounts/me/deposit", alice, "application/json", `{"amount": 1.5}`)
		assert.Equal(t, http.StatusBadRequest, status)
		status, _ = f.rest(t, http.MethodPost, "/accounts/me/deposit", alice, "application/json", `{"amount": -5}`)
		assert.Equal(t, http.StatusBadRequest, status)
		status, _ = f.rest(t, http.MethodPost, "/accounts/me/deposit", alice, "application/json", `{"amount": 5, "to": "bob"}`)
		assert.Equal(t, http.StatusBadRequest, status)
	})

	t.Run("accounts are per sub", func(t *testing.T) {
		bob := f.token(t, f.bank.APIURL(), map[string]any{"sub": "bob"})
		_, out := f.rest(t, http.MethodGet, "/accounts/me", bob, "", "")
		assert.Equal(t, "bob", out.Result.Account)
		assert.Equal(t, OpeningBalance, out.Result.Balance)
	})

	t.Run("a workload identity shows its principal", func(t *testing.T) {
		agent := f.token(t, f.bank.APIURL(), map[string]any{"sub": "wid:root:auth_jwt_1:agent-1"})
		_, out := f.rest(t, http.MethodGet, "/accounts/me", agent, "", "")
		assert.Equal(t, "agent-1", out.Result.Account)
	})

	t.Run("a person never opens an agent's own account", func(t *testing.T) {
		const wid = "wid:root:auth_jwt_1:agent-9"
		agent := f.token(t, f.bank.APIURL(), map[string]any{"sub": wid})
		status, _ := f.rest(t, http.MethodPost, "/accounts/me/withdraw", agent, "application/json", `{"amount": 100}`)
		require.Equal(t, http.StatusOK, status)

		// A person whose sub spells the agent's workload identity, acted for.
		person := f.token(t, f.bank.APIURL(), map[string]any{"sub": wid, "act": map[string]any{"sub": "wid:root:auth_jwt_1:agent-1"}})
		_, out := f.rest(t, http.MethodGet, "/accounts/me", person, "", "")
		assert.Equal(t, OpeningBalance, out.Result.Balance, "their own account, untouched")
		assert.Equal(t, wid, out.Result.Account, "named by their sub")
	})
}

// The bank accepts only a token its authorization server issued for that face:
// not the agent's own identity, and not a token for the other face.
func TestBank_RefusesForeignTokens(t *testing.T) {
	f := newBankFixture(t)
	identity, err := f.idp.Mint(Identity{Kind: KindAgent, Subject: "agent-1"})
	require.NoError(t, err)
	mcpToken := f.token(t, f.bank.MCPURL(), map[string]any{"sub": "agent-1"})
	other, err := NewIdP("https://localhost:8410")
	require.NoError(t, err)
	forged, err := other.sign(map[string]any{"sub": "agent-1", "aud": f.bank.APIURL()}, time.Minute)
	require.NoError(t, err)
	// Within the JWT library's default minute of leeway, past the bank's own.
	expired, err := f.idp.sign(map[string]any{"sub": "agent-1", "aud": f.bank.APIURL()}, -30*time.Second)
	require.NoError(t, err)

	for name, token := range map[string]string{
		"no token":                      "",
		"the agent's identity":          identity,
		"a token for the MCP face":      mcpToken,
		"a token signed by another key": forged,
		"a token expired 30s ago":       expired,
	} {
		t.Run(name, func(t *testing.T) {
			status, _ := f.rest(t, http.MethodGet, "/accounts/me", token, "", "")
			assert.Equal(t, http.StatusUnauthorized, status)
		})
	}
}

// bearerTransport attaches a token to every request, as Warden does upstream.
type bearerTransport struct{ token string }

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}

func (f *bankFixture) mcpSession(t *testing.T, token string) *mcp.ClientSession {
	t.Helper()
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	session, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint:   f.server.URL + BankMCPPath + "/",
		HTTPClient: &http.Client{Transport: bearerTransport{token}},
		MaxRetries: -1,
	}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { session.Close() })
	return session
}

func toolResult(t *testing.T, res *mcp.CallToolResult) ToolResult {
	t.Helper()
	raw, err := json.Marshal(res.StructuredContent)
	require.NoError(t, err)
	var out ToolResult
	require.NoError(t, json.Unmarshal(raw, &out))
	return out
}

func TestBank_MCP(t *testing.T) {
	f := newBankFixture(t)
	session := f.mcpSession(t, f.token(t, f.bank.MCPURL(), map[string]any{
		"sub": "alice", "act": map[string]any{"sub": "wid:root:auth_jwt_1:agent-1"},
	}))
	ctx := context.Background()

	tools, err := session.ListTools(ctx, nil)
	require.NoError(t, err)
	var names []string
	for _, tool := range tools.Tools {
		names = append(names, tool.Name)
		// An agent reports what it was asked for; the token is the lesson, so
		// every tool asks for it to be shown.
		assert.Contains(t, tool.Description, "show the user that token's iss, aud, sub, act", tool.Name)
	}
	assert.ElementsMatch(t, []string{"get_balance", "withdraw", "deposit", "close_account"}, names,
		"the bank offers all four; Warden's policy is what hides close_account")

	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "withdraw", Arguments: map[string]any{"amount": 50}})
	require.NoError(t, err)
	assert.False(t, res.IsError)
	out := toolResult(t, res)
	assert.Equal(t, "withdraw", out.Tool)
	assert.Equal(t, "alice", out.Result.Account)
	assert.Equal(t, int64(950), out.Result.Balance)
	assert.Equal(t, "alice", out.AccessToken["sub"])
	assert.Equal(t, map[string]any{"sub": "wid:root:auth_jwt_1:agent-1"}, out.AccessToken["act"])

	res, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "withdraw", Arguments: map[string]any{"amount": 5000}})
	require.NoError(t, err)
	assert.True(t, res.IsError, "an overdraft is a tool error, not a protocol one")
	out = toolResult(t, res)
	assert.Equal(t, "insufficient funds", out.Error)
	assert.NotEmpty(t, out.AccessToken)

	res, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "close_account"})
	require.NoError(t, err)
	assert.True(t, toolResult(t, res).Result.Closed)
	res, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "get_balance"})
	require.NoError(t, err)
	assert.Equal(t, OpeningBalance, toolResult(t, res).Result.Balance, "a closed account reopens")
}

// The MCP face, like the REST one, takes only a token issued for it.
func TestBank_MCPRefusesForeignTokens(t *testing.T) {
	f := newBankFixture(t)
	identity, err := f.idp.Mint(Identity{Kind: KindAgent, Subject: "agent-1"})
	require.NoError(t, err)

	for name, token := range map[string]string{
		"the agent's identity":      identity,
		"a token for the REST face": f.token(t, f.bank.APIURL(), map[string]any{"sub": "alice"}),
	} {
		t.Run(name, func(t *testing.T) {
			client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
			_, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{
				Endpoint:   f.server.URL + BankMCPPath,
				HTTPClient: &http.Client{Transport: bearerTransport{token}},
				MaxRetries: -1,
			}, nil)
			require.Error(t, err)
		})
	}
}

// The bank refuses an amount it cannot use, whatever Warden's policy let
// through: it is the last line, not the only one.
func TestBank_MCPAmounts(t *testing.T) {
	f := newBankFixture(t)
	session := f.mcpSession(t, f.token(t, f.bank.MCPURL(), map[string]any{"sub": "wid:root:auth_jwt_1:agent-1"}))
	ctx := context.Background()

	for name, amount := range map[string]any{
		"zero":         0,
		"negative":     -5,
		"fractional":   1.5,
		"over the max": maxAmount + 1,
	} {
		t.Run(name, func(t *testing.T) {
			res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "withdraw", Arguments: map[string]any{"amount": amount}})
			require.NoError(t, err)
			assert.True(t, res.IsError)
			assert.Contains(t, toolResult(t, res).Error, "whole number")
		})
	}

	for name, args := range map[string]map[string]any{
		"not a number": {"amount": "500"},
		"a list":       {"amount": []any{500}},
		"missing":      {},
	} {
		t.Run(name, func(t *testing.T) {
			res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "withdraw", Arguments: args})
			assert.True(t, err != nil || res.IsError, "refused by the input schema")
		})
	}

	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "get_balance"})
	require.NoError(t, err)
	assert.Equal(t, OpeningBalance, toolResult(t, res).Result.Balance, "nothing moved")
}

// Concurrent operations on one account never lose an update.
func TestBank_ConcurrentDeposits(t *testing.T) {
	f := newBankFixture(t)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f.bank.deposit("alice", 1)
		}()
	}
	wg.Wait()
	assert.Equal(t, OpeningBalance+50, f.bank.getBalance("alice").Balance)
}
