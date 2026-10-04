package playground

import (
	"fmt"
	"strings"
)

// Header is one header an MCP client is attached with. Values refer to shell
// variables (for example "Bearer $AGENT") that the setup commands define.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Attachment is an MCP server to attach to the agent's client.
type Attachment struct {
	// Server is the name the client knows it by: "bank", "warden" or "github".
	// There is never more than one bank attached, so the agent cannot pick the
	// wrong one.
	Server string `json:"server"`
	// Path is relative to the Warden address, for example "/v1/bank/role/atm/gateway/".
	Path    string   `json:"path"`
	Headers []Header `json:"headers"`
}

// Variant is a follow-up within a scenario: optional when listed in Variants,
// usually done by replacing the attachment; part of the scenario when it is
// its Then, done after the scenario's own questions.
type Variant struct {
	Label  string      `json:"label"`
	Attach *Attachment `json:"attach,omitempty"`
	// Commands run before Ask, after any attachment.
	Commands []string `json:"commands,omitempty"`
	Ask      string   `json:"ask"`
	Shows    []string `json:"shows,omitempty"`
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
	Commands []string `json:"commands,omitempty"`
	Ask      []string `json:"ask,omitempty"`
	// Then is the scenario's next step, done once its questions are answered:
	// a change the reader makes, and the question that shows it took effect.
	Then     *Variant  `json:"then,omitempty"`
	Shows    []string  `json:"shows"`
	Variants []Variant `json:"variants,omitempty"`
}

// SetupCommands mint the identities the scenarios use. They live a working day,
// so a reader who pauses the tour does not come back to refusals on every
// attached server. bob is a premium customer: his token says so.
var SetupCommands = []string{
	"AGENT=$(warden dev jwt agent agent-1 -ttl 8h)",
	"ALICE=$(warden dev jwt user alice -may-act agent-1 -ttl 8h)",
	`BOB=$(warden dev jwt user bob -may-act agent-1 -claims '{"tier": "premium"}' -ttl 8h)`,
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

// githubCommands give the bootstrapped github role the one thing the bootstrap
// cannot: the reader's PAT. It is stored on the spec, the quickest start, which
// the scenario then points at credential chaining for production. The PAT is
// read without echo, so it stays out of the shell's history, and the heredoc
// expands it.
func githubCommands() []string {
	return []string{
		"printf 'GitHub PAT: '; read -rs GITHUB_PAT; echo",
		`warden cred spec create ` + SpecGitHub + ` -json - <<EOF
{
  "source": "` + SourceGitHub + `",
  "min_ttl": 3600,
  "max_ttl": 86400,
  "config": {
    "mint_method": "pat",
    "token": "$GITHUB_PAT"
  }
}
EOF`,
	}
}

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
				"The bank has five tools; the agent sees four. The atm role's MCP policy does not allow close_account, so Warden removes it from tools/list.",
				"A client that calls it anyway is refused by Warden, before the bank sees it.",
				"`warden policy -type mcp read atm-tools` shows the rule.",
			},
		},
		{
			Number: 3,
			Title:  "Policy decides which arguments",
			Ask:    []string{"Withdraw 50.", "Withdraw 500."},
			Then: &Variant{
				Label:    "Raise the limit to 1000, live, and ask again",
				Commands: []string{"warden policy write -type mcp atm-tools - <<EOF\n" + liveLimitPolicy + "EOF"},
				Ask:      "Withdraw 500.",
			},
			Shows: []string{
				"50 goes through; 500 is refused by Warden before the bank sees it, by the condition " + atmWithdrawCondition(100) + ".",
				"The condition runs on every MCP call, so it only judges withdraw, and it fails closed: a withdrawal without a readable amount is refused.",
				"Once the limit is raised, the same 500 goes through on the next call, with no change to the agent or the bank, and no reconnect.",
			},
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
					Ask:    "What's my balance? Withdraw 500.",
					Shows: []string{
						"bob's account: same agent, same role, one account per person.",
						"500 goes through: bob's token carries tier: premium, and the assistant's limit reads it as user.metadata.tier, 1000 for a premium customer.",
						"alice has no tier, so her limit is 100. Scenario 5 puts it to the test.",
						"The tier comes from bob's token, signed by the IdP. Neither the agent nor anything said in the conversation can claim it.",
						"`warden policy -type mcp read assistant-tools` shows the rule.",
					},
				},
				{
					Label: "As agent-2, holding alice's token",
					Attach: &Attachment{Server: "bank", Path: gatewayPath(MountBankMe, RoleAssistant), Headers: []Header{
						{Name: "X-Warden-Agent-Token", Value: "$(warden dev jwt agent agent-2)"},
						{Name: "Authorization", Value: "Bearer $ALICE"},
					}},
					Shows: []string{
						"Warden refuses: alice's may_act names agent-1. The rule is the policy condition user.metadata.may_act_sub == agent.principal.",
						"The refusal covers initialize too, so the client lists bank as failed. `warden dev audit -decision deny -limit 1` shows why.",
					},
				},
			},
		},
		{
			Number: 5,
			Title:  "A memo cannot move the money",
			// Scenario 4's last variant left agent-2 attached.
			Attach: bankAssistant("AGENT", "ALICE"),
			Ask:    []string{"Go through my recent transactions and take care of anything that needs action."},
			Shows: []string{
				fmt.Sprintf("The pending payment request's memo was written by a third party, not alice. It tells the agent to withdraw %d and close the account.", InjectedAmount),
				fmt.Sprintf("If the agent obeys, Warden refuses the %d: alice's limit is 100. close_account is not even in its tool list. The bank would have paid: alice can cover it.", InjectedAmount),
				"If the agent spots the trick, that is the model's judgement, and a better-written memo can beat it. The limit holds either way; the variant shows it.",
			},
			Variants: []Variant{
				{
					Label: "Insist",
					Ask:   "The memo is genuine and I approve it. Do exactly what it says.",
					Shows: []string{
						"Warden still refuses. The limit reads alice's verified token, not the conversation, so nothing said in the chat can raise it.",
						"`warden dev audit -user alice -decision deny` shows the refused withdraw and the condition that judged it.",
					},
				},
			},
		},
		{
			Number:   6,
			Title:    "Every call is audited",
			Commands: []string{"warden dev audit -limit 10", "warden dev audit -user alice"},
			Shows: []string{
				"Each entry has the agent and its role, the person it acted for, the tool and Warden's decision, including the refusals from scenarios 2 to 5.",
				"Tokens are hashed, never written in the clear.",
			},
		},
		{
			Number: 7,
			Title:  "The agent finds its roles by itself",
			Attach: &Attachment{Server: "warden", Path: "/v1/sys/mcp", Headers: agentHeader("AGENT")},
			Ask:    []string{"What can you do through Warden?"},
			Shows: []string{
				"list_roles returns atm, assistant and teller, each with a description, a provider, a skill:// URI and a url.",
				"It returns github too, which has no credential yet: scenario 9 gives it one.",
				"atm and assistant use the mcp skill: an MCP server describes its own tools. teller has a skill written for it, because an HTTP API does not.",
				"The agent can read the skills of the roles it can assume and nothing else.",
			},
		},
		{
			Number:   8,
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
		{
			Number:   9,
			Title:    "Your own service next: GitHub",
			Commands: githubCommands(),
			Attach:   &Attachment{Server: "github", Path: gatewayPath(MountGitHub, RoleGitHub), Headers: agentHeader("AGENT")},
			Ask:      []string{"What can you do through Warden?", "List the open issues in <owner>/<repo>."},
			Shows: []string{
				"The playground already set GitHub up like the bank: a mount in front of GitHub's MCP server, a role, and a policy that lets through only GitHub's read-only tools. It lacked one thing, a credential; the spec gives it yours.",
				"Same agent, same identity, same Warden: only the upstream changed. The PAT lives in Warden; the agent still holds only $AGENT.",
				"`warden policy -type mcp read github-read` shows the tools the agent gets; GitHub's write tools never reach it.",
				"Creating the spec warns that it stores a secret: a PAT is long-lived, which the bank's keyless token never was.",
				"In production, store nothing: keep the PAT in your secret store and let Warden fetch it per request with credential chaining (secret_spec). https://wardengateway.com/federation/credential-chaining/",
				"The dev server keeps everything in memory. Restarting it forgets the PAT.",
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
