package playground

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testSettings() Settings {
	return Settings{
		WardenIssuer: "http://127.0.0.1:8400",
		ASURL:        "https://localhost:8410",
		BankURL:      "https://localhost:8420",
		CAPEM:        "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
		AuditPath:    "/tmp/playground-audit.log",
	}
}

func stepIndex(steps []Step, path string) int {
	for i, s := range steps {
		if s.Path == path {
			return i
		}
	}
	return -1
}

// The playground teaches by example, so the configuration it writes must be what
// someone should copy: verified TLS throughout.
func TestBootstrap_NeverSkipsTLSVerification(t *testing.T) {
	raw, err := json.Marshal(Bootstrap(testSettings()))
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "tls_skip_verify")
	assert.NotContains(t, string(raw), "http://localhost", "fixtures are reached over https")
}

func TestBootstrap_Order(t *testing.T) {
	steps := Bootstrap(testSettings())
	before := func(first, second string) {
		t.Helper()
		i, j := stepIndex(steps, first), stepIndex(steps, second)
		require.NotEqual(t, -1, i, first)
		require.NotEqual(t, -1, j, second)
		assert.Less(t, i, j, "%s must come before %s", first, second)
	}
	before("sys/auth/agent", "auth/agent/config")
	before("sys/providers/bank-api", "sys/skills/teller") // the rest skill it requires is seeded on mount
	before("sys/skills/teller", "auth/agent/role/teller")
	before("sys/cred/sources/bank-as", "sys/cred/specs/bank-agent")
	before("sys/cred/specs/bank-agent", "auth/agent/role/atm")
	before("sys/policies/mcp/atm-tools", "auth/agent/role/atm")
	before("sys/providers/github-mcp", "github-mcp/config")
	before("sys/policies/mcp/github-read", "auth/agent/role/github")
	assert.Equal(t, "sys/audit/playground", steps[len(steps)-1].Path, "audit last, so the log holds the scenarios")

	seen := map[string]bool{}
	for _, s := range steps {
		assert.False(t, seen[s.Path], "duplicate step %s", s.Path)
		seen[s.Path] = true
		assert.Contains(t, []string{"create", "update"}, s.Operation, s.Path)
	}
}

// Discovery reads a role's provider and skill from its fields, so descriptions
// stay prose.
func TestBootstrap_Roles(t *testing.T) {
	steps := Bootstrap(testSettings())
	want := map[string]string{RoleATM: "bank/", RoleAssistant: "bank-me/", RoleTeller: "bank-api/", RoleGitHub: "github-mcp/"}
	for role, mount := range want {
		i := stepIndex(steps, "auth/agent/role/"+role)
		require.NotEqual(t, -1, i, role)
		data := steps[i].Data
		assert.Equal(t, mount, data["provider_path"], role)
		assert.Equal(t, []string{AudienceAgent}, data["bound_audiences"], role)
		desc := data["description"].(string)
		assert.NotContains(t, desc, "skill:", role)
		assert.NotContains(t, desc, "url:", role)
	}
	assert.Equal(t, SkillTeller, steps[stepIndex(steps, "auth/agent/role/teller")].Data["skill"])
	assert.NotContains(t, steps[stepIndex(steps, "auth/agent/role/atm")].Data, "skill", "an MCP role uses the mcp skill by default")
}

// The assistant's policies read may_act and the tier from the person's token,
// so the user role must surface both as metadata.
func TestBootstrap_UserMetadata(t *testing.T) {
	steps := Bootstrap(testSettings())
	claims := steps[stepIndex(steps, "auth/user/role/user")].Data["metadata_claims"].(map[string]any)
	assert.Equal(t, "may_act_sub", claims["/may_act/sub"])
	assert.Equal(t, "tier", claims["/tier"])
}

func TestBootstrap_KeylessSource(t *testing.T) {
	steps := Bootstrap(testSettings())
	src := steps[stepIndex(steps, "sys/cred/sources/bank-as")].Data["config"].(map[string]any)
	assert.Equal(t, "none", src["client_auth"])
	for _, secret := range []string{"client_secret", "private_key", "secret_spec"} {
		assert.NotContains(t, src, secret)
	}

	onBehalf := steps[stepIndex(steps, "sys/cred/specs/bank-on-behalf")].Data["config"].(map[string]any)
	assert.Equal(t, "warden_identity", onBehalf["subject_token_source"])
	assert.Equal(t, "sub", onBehalf["assertion_user_claims"], "one assertion carries the person and the agent")
	assert.Equal(t, "https://localhost:8410", onBehalf["assertion_audience"])
	assert.Equal(t, "https://localhost:8420/mcp", onBehalf["audience"])

	api := steps[stepIndex(steps, "sys/cred/specs/bank-api-agent")].Data["config"].(map[string]any)
	assert.Equal(t, "https://localhost:8420/api", api["audience"])
}

func TestBootstrap_Policies(t *testing.T) {
	// Every policy covers the one gateway shape the tour uses: the role in the path.
	for name, policy := range map[string]string{
		"bank-access": policyBankAccess, "atm-tools": policyATMTools,
		"assistant-on-behalf": policyAssistantOnBehalf, "assistant-tools": policyAssistantTools,
		"github-access": policyGitHubAccess, "github-read": policyGitHubRead,
	} {
		assert.Equal(t, 1, strings.Count(policy, "path \""), name)
		assert.Contains(t, policy, "/role/+/gateway*", name)
	}
	for _, route := range []string{"accounts/me\"", "accounts/me/deposit\"", "accounts/me/withdraw\""} {
		assert.Contains(t, policyTellerAPI, "bank-api/role/+/gateway/"+route, "one stanza per route")
	}
	assert.Contains(t, policyATMTools, "call.tool != 'withdraw' ||", "the limit judges withdraw only")
	assert.Contains(t, policyATMTools, "has(call.args.amount)", "a withdrawal without a readable amount fails closed")
	assert.NotContains(t, policyATMTools, "orValue", "a default would let an unreadable amount through")
	assert.NotContains(t, policyATMTools, "close_account")
	assert.Contains(t, liveLimitPolicy, "call.args.amount <= 400")
	assert.Contains(t, policyAssistantOnBehalf, "user.metadata.may_act_sub == agent.principal")
	assert.Contains(t, policyAssistantTools, "call.tool != 'withdraw' ||", "the person's limit judges withdraw only")
	assert.Contains(t, policyAssistantTools, "has(call.args.amount)", "a withdrawal without a readable amount fails closed")
	assert.Contains(t, policyAssistantTools, "has(user.metadata.tier)", "a person without a tier gets the lower limit")
	assert.NotContains(t, policyAssistantTools, "orValue", "dotted access, so the audit records the tier it read")
	assert.Contains(t, policyTellerAPI, "has(request.data.amount)", "the body condition fails closed")
	assert.NotContains(t, policyTellerAPI, "orValue", "a default would let an unread body through")
}

// The teller skill documents the bank's REST face; it must not drift from it.
func TestTellerSkill_MatchesTheBank(t *testing.T) {
	for _, route := range []string{"GET accounts/me", "POST accounts/me/deposit", "POST accounts/me/withdraw"} {
		assert.Contains(t, tellerSkill, route)
	}
	f := newBankFixture(t)
	token := f.token(t, f.bank.APIURL(), map[string]any{"sub": "agent-1"})
	status, _ := f.rest(t, "GET", "/accounts/me", token, "", "")
	assert.Equal(t, 200, status)
	status, _ = f.rest(t, "POST", "/accounts/me/deposit", token, "application/json", `{"amount": 1}`)
	assert.Equal(t, 200, status)
	status, _ = f.rest(t, "POST", "/accounts/me/withdraw", token, "application/json", `{"amount": 1}`)
	assert.Equal(t, 200, status)
	assert.Contains(t, tellerSkill, "over 100", "the skill states the limit the policy enforces")
	assert.Contains(t, tellerSkill, "Show the token with every answer", "the REST face asks for the token too")
	assert.Contains(t, tellerSkill, "as pretty-printed JSON", "rendered whole, not summarised")
}

func TestScenarios(t *testing.T) {
	scenarios := Scenarios()
	require.Len(t, scenarios, 9)
	for i, s := range scenarios {
		assert.Equal(t, i+1, s.Number)
		assert.NotEmpty(t, s.Title)
		assert.NotEmpty(t, s.Shows, s.Title)
		// One bank at a time: scenarios replace the bank attachment, never add a
		// second one beside it.
		for _, a := range append([]*Attachment{s.Attach}, variantAttachments(s)...) {
			if a != nil {
				assert.Contains(t, []string{"bank", "warden", "github"}, a.Server, s.Title)
			}
		}
	}
	assert.Equal(t, []string{"bank"}, scenarios[7].Detach, "the REST scenario removes the MCP bank")
	assert.Nil(t, scenarios[7].Attach, "and keeps the same identity and discovery server")
}

func variantAttachments(s Scenario) []*Attachment {
	var out []*Attachment
	for _, v := range s.Variants {
		out = append(out, v.Attach)
	}
	return out
}

func TestClaudeAddCommand(t *testing.T) {
	a := &Attachment{Server: "bank", Path: "/v1/bank-me/role/assistant/gateway/", Headers: onBehalfHeaders("AGENT", "ALICE")}
	assert.Equal(t,
		`claude mcp add --transport http bank "http://127.0.0.1:8400/v1/bank-me/role/assistant/gateway/" \`+"\n"+
			`  --header "X-Warden-Agent-Token: $AGENT" \`+"\n"+
			`  --header "Authorization: Bearer $ALICE"`,
		ClaudeAddCommand(a, "http://127.0.0.1:8400"))
}
