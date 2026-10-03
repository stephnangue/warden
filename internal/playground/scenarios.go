package playground

import "strings"

// Header is one header an MCP client is attached with. Values refer to shell
// variables (for example "Bearer $AGENT") that the setup commands define.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Attachment is an MCP server to attach to the agent's client.
type Attachment struct {
	// Server is the name the client knows it by: "bank" or "warden". There is
	// never more than one bank attached, so the agent cannot pick the wrong one.
	Server string `json:"server"`
	// Path is relative to the Warden address, for example "/v1/bank/role/atm/gateway/".
	Path    string   `json:"path"`
	Headers []Header `json:"headers"`
}

// Variant is an optional follow-up within a scenario, done by replacing the
// attachment.
type Variant struct {
	Label  string      `json:"label"`
	Attach *Attachment `json:"attach,omitempty"`
	Ask    string      `json:"ask"`
	Shows  []string    `json:"shows"`
}

// Scenario is one idea about how Warden works, with what to do and what to look
// for. Scenarios run in order; one that leaves Attach nil keeps the previous
// attachment.
type Scenario struct {
	Number int    `json:"number"`
	Title  string `json:"title"`
	// Detach names servers to remove before anything else.
	Detach []string `json:"detach,omitempty"`
	// Attach replaces the server of the same name. Nil keeps what is attached.
	Attach *Attachment `json:"attach,omitempty"`
	// Commands are shell commands to run, in order, besides attaching.
	Commands []string  `json:"commands,omitempty"`
	Ask      []string  `json:"ask,omitempty"`
	Shows    []string  `json:"shows"`
	Variants []Variant `json:"variants,omitempty"`
}

// SetupCommands mint the identities the scenarios use.
var SetupCommands = []string{
	"AGENT=$(warden dev jwt agent agent-1)",
	"ALICE=$(warden dev jwt user alice -may-act agent-1)",
	"BOB=$(warden dev jwt user bob -may-act agent-1)",
}

func agentHeader(variable string) []Header {
	return []Header{{Name: "Authorization", Value: "Bearer $" + variable}}
}

func onBehalfHeaders(agentVar, userVar string) []Header {
	return []Header{
		{Name: "X-Warden-Agent-Token", Value: "$" + agentVar},
		{Name: "Authorization", Value: "Bearer $" + userVar},
	}
}

func gatewayPath(mount, role string) string {
	return "/v1/" + mount + "/role/" + role + "/gateway/"
}

// liveLimitPolicy is scenario 3's live edit: the same tool policy with a larger
// withdrawal limit.
var liveLimitPolicy = gatewayMCP(MountBank, atmToolRules(1000))

// Scenarios is the playground's tour, one idea at a time.
func Scenarios() []Scenario {
	bankATM := &Attachment{Server: "bank", Path: gatewayPath(MountBank, RoleATM), Headers: agentHeader("AGENT")}
	bankAssistant := func(agentVar, userVar string) *Attachment {
		return &Attachment{Server: "bank", Path: gatewayPath(MountBankMe, RoleAssistant), Headers: onBehalfHeaders(agentVar, userVar)}
	}

	return []Scenario{
		{
			Number: 1,
			Title:  "The agent shows only its identity; Warden brings the credential",
			Attach: bankATM,
			Ask:    []string{"What's my balance?"},
			Shows: []string{
				"The agent sent its own JWT, issued by the playground IdP.",
				"The bank received a different token: access_token.iss is the bank's authorization server, aud is the bank, exp is five minutes away.",
				"Warden got that token by proving the agent's identity with an assertion signed by its own OIDC issuer. No secret is stored anywhere: `warden cred source read " + SourceBankAS + "` shows none.",
				"The agent never saw the bank token.",
				"The agent is asked to show the token's claims with every answer. If it does not, expand the raw tool result (ctrl+o in Claude Code) and read access_token.",
			},
		},
		{
			Number: 2,
			Title:  "Policy decides which tools",
			Ask:    []string{"Close my account."},
			Shows: []string{
				"The bank has four tools; the agent sees three. The atm role's MCP policy does not allow close_account, so Warden removes it from tools/list.",
				"A client that calls it anyway is refused by Warden, before the bank sees it.",
				"`warden policy -type mcp read atm-tools` shows the rule.",
			},
		},
		{
			Number: 3,
			Title:  "Policy decides which arguments",
			Ask:    []string{"Withdraw 50.", "Withdraw 500."},
			Shows: []string{
				"50 goes through; 500 is refused by Warden before the bank sees it, by the condition " + atmWithdrawCondition(100) + ".",
				"The condition runs on every MCP call, so it only judges withdraw, and it fails closed: a withdrawal without a readable amount is refused.",
				"Raise the limit with the command below; the next call follows it, with no change to the agent or the bank.",
			},
			Commands: []string{"warden policy write -type mcp atm-tools - <<EOF\n" + liveLimitPolicy + "EOF"},
		},
		{
			Number: 4,
			Title:  "The agent acts for a person",
			Attach: bankAssistant("AGENT", "ALICE"),
			Ask:    []string{"What's my balance? Withdraw 50."},
			Shows: []string{
				"access_token.sub is alice and act.sub is the agent: the bank debits alice's account, not the agent's.",
				"One token carries both. Warden's assertion names alice as sub and the agent in act, and the authorization server copies both.",
			},
			Variants: []Variant{
				{
					Label:  "As bob",
					Attach: bankAssistant("AGENT", "BOB"),
					Ask:    "What's my balance?",
					Shows:  []string{"bob's account: same agent, same role, one account per person."},
				},
				{
					Label: "As agent-2, holding alice's token",
					Attach: &Attachment{Server: "bank", Path: gatewayPath(MountBankMe, RoleAssistant), Headers: []Header{
						{Name: "X-Warden-Agent-Token", Value: "$(warden dev jwt agent agent-2)"},
						{Name: "Authorization", Value: "Bearer $ALICE"},
					}},
					Shows: []string{
						"Warden refuses: alice's may_act names agent-1. The rule is the policy condition user.metadata.may_act_sub == agent.principal.",
						"The refusal covers initialize too, so the client lists bank as failed. `warden dev audit -decision deny -n 1` shows why.",
					},
				},
			},
		},
		{
			Number:   5,
			Title:    "Every call is audited",
			Commands: []string{"warden dev audit -n 10", "warden dev audit -user alice"},
			Shows: []string{
				"Each entry has the agent and its role, the person it acted for, the tool and Warden's decision, including the refusals from scenarios 2 to 4.",
				"Tokens are hashed, never written in the clear.",
			},
		},
		{
			Number: 6,
			Title:  "The agent finds its roles by itself",
			Attach: &Attachment{Server: "warden", Path: "/v1/sys/mcp", Headers: agentHeader("AGENT")},
			Ask:    []string{"What can you do through Warden?"},
			Shows: []string{
				"list_roles returns atm, assistant and teller, each with a description, a provider, a skill:// URI and a url.",
				"atm and assistant use the mcp skill: an MCP server describes its own tools. teller has a skill written for it, because an HTTP API does not.",
				"The agent can read the skills of the roles it can assume and nothing else.",
			},
		},
		{
			Number:   7,
			Title:    "The same bank, as a plain HTTP API",
			Detach:   []string{"bank"},
			Commands: []string{"export AGENT WARDEN_ADDR"},
			Ask:      []string{"Check my balance, deposit 30, then withdraw 500."},
			Shows: []string{
				"With no bank tool attached, the agent turns to discovery and picks teller: provider rest, with a url it can call itself.",
				"It reads skill://teller/SKILL.md and calls the API with its own JWT. The bank still receives a token of its own.",
				"The withdrawal of 500 is refused by a policy condition on the JSON body, written to fail closed: has(request.data.amount) && request.data.amount <= 100.",
				"If the agent asks which bank, answer: the one you can reach through Warden.",
			},
		},
	}
}

// ClaudeAddCommand renders the claude mcp add line for an attachment.
func ClaudeAddCommand(a *Attachment, wardenAddr string) string {
	var b strings.Builder
	b.WriteString("claude mcp add --transport http " + a.Server + ` "` + wardenAddr + a.Path + `"`)
	for _, h := range a.Headers {
		b.WriteString(` \` + "\n  --header \"" + h.Name + ": " + h.Value + `"`)
	}
	return b.String()
}
