package playground

import (
	_ "embed"
	"fmt"
	"strings"
	"time"
)

// Names of everything the bootstrap creates. Kept together because the bootstrap,
// the scenario catalogue and the tests all have to agree on them.
const (
	AgentAuthMount = "agent"
	UserAuthMount  = "user"
	UserRole       = "user"

	MountBank    = "bank"     // the bank's MCP face, agent only
	MountBankMe  = "bank-me"  // the same face, acting for a person
	MountBankAPI = "bank-api" // the bank's REST face

	RoleATM       = "atm"
	RoleAssistant = "assistant"
	RoleTeller    = "teller"

	SourceBankAS     = "bank-as"
	SpecBankAgent    = "bank-agent"
	SpecBankOnBehalf = "bank-on-behalf"
	SpecBankAPIAgent = "bank-api-agent"

	// GitHub's hosted MCP server, set up like the bank's MCP face but for its
	// credential: the spec holds the reader's PAT, so the reader creates it
	// (scenario 9) and until then the role has nothing to mint.
	SourceGitHub = "github"
	SpecGitHub   = "github-pat"
	MountGitHub  = "github-mcp"
	RoleGitHub   = "github"

	githubMCPURL = "https://api.githubcopilot.com/mcp"

	SkillTeller = "teller"
	AuditDevice = "playground"

	// wardenClientID is how the bank's authorization server knows Warden. It is
	// an identifier, not a credential: Warden is a public client.
	wardenClientID = "warden"
)

//go:embed skills/teller.md
var tellerSkill string

// Settings are the run-time values the bootstrap is built from.
type Settings struct {
	// WardenIssuer is the issuer URL Warden's OIDC issuer is enabled with.
	WardenIssuer string
	// ASURL is the IdP and authorization server; BankURL the bank.
	ASURL   string
	BankURL string
	// CAPEM is the fixtures' CA, in PEM form.
	CAPEM string
	// AuditPath is where the playground's file audit device writes.
	AuditPath string
}

func (s Settings) bankMCPURL() string { return strings.TrimRight(s.BankURL, "/") + BankMCPPath }
func (s Settings) bankAPIURL() string { return strings.TrimRight(s.BankURL, "/") + BankAPIPath }

// Step is one write the bootstrap makes, in order, as the root token.
type Step struct {
	// Path is relative to /v1, e.g. "sys/auth/agent".
	Path string
	// Operation is "create" or "update".
	Operation string
	Data      map[string]any
	// Note says what the step is for, for logs and for anyone rebuilding the
	// playground by hand.
	Note string
}

// Policies the bootstrap writes. Every one covers both gateway shapes, since the
// role-in-path one and the bare one are matched independently.
var (
	policyBankAccess = gatewayCBP(MountBank, "")

	// The withdrawal limit runs on every MCP call, initialize and tools/list
	// included, so it judges withdraw only. It fails closed: a withdrawal whose
	// amount Warden cannot read — missing, null, a list — has no scalar amount, so
	// has() is false and it is refused rather than let through.
	policyATMTools = gatewayMCP(MountBank, atmToolRules(100))

	// The person must have let this very agent act for them: may_act on their
	// token names it. The binding is policy, readable and changeable, not a rule
	// buried in core.
	policyAssistantOnBehalf = gatewayCBP(MountBankMe,
		`  condition = "user.present && user.metadata.may_act_sub == agent.principal"`)

	// The person's limit comes from their own verified token: a premium customer
	// may withdraw more. Like the ATM's, it judges withdraw only and fails closed.
	policyAssistantTools = gatewayMCP(MountBankMe,
		`  methods { allowed = ["tools/list", "tools/call"] }
  tools   { allowed = ["get_balance", "get_transactions", "withdraw", "deposit"] }
  condition = "`+assistantWithdrawCondition()+`"`)

	// The REST face reads the withdrawal body. The condition fails closed: a body
	// Warden did not read has no amount, so it is refused rather than let through.
	policyTellerAPI = restRouteCBP("accounts/me", `["read"]`, "") +
		restRouteCBP("accounts/me/deposit", `["create", "update"]`, "") +
		restRouteCBP("accounts/me/withdraw", `["create", "update"]`,
			`has(request.data.amount) && request.data.amount <= 100`)

	// GitHub's read-only tools: its write tools never reach the agent.
	policyGitHubAccess = gatewayCBP(MountGitHub, "")
	policyGitHubRead   = gatewayMCP(MountGitHub,
		`  methods { allowed = ["tools/list", "tools/call"] }
  tools   { allowed = ["get_me", "get_file_contents", "list_issues", "issue_read", "list_pull_requests", "pull_request_read", "search_code", "search_issues"] }`)
)

// atmWithdrawCondition is the ATM's withdrawal limit, as a policy condition.
func atmWithdrawCondition(limit int) string {
	return fmt.Sprintf("call.tool != 'withdraw' || (has(call.args.amount) && call.args.amount <= %d)", limit)
}

// assistantWithdrawCondition is the withdrawal limit of a person an agent acts
// for: 1000 for a premium customer, 100 otherwise. The tier is read with dotted
// access, which the audit records among the condition's inputs; a person whose
// token carries no tier has an empty metadata map, so has() is false.
func assistantWithdrawCondition() string {
	return "call.tool != 'withdraw' || (has(call.args.amount) && call.args.amount <= " +
		"(has(user.metadata.tier) && user.metadata.tier == 'premium' ? 1000 : 100))"
}

// atmToolRules is the body of the ATM's tool policy, with the given limit.
func atmToolRules(limit int) string {
	return `  methods { allowed = ["tools/list", "tools/call"] }
  tools   { allowed = ["get_balance", "get_transactions", "withdraw", "deposit"] }
  condition = "` + atmWithdrawCondition(limit) + `"`
}

const gatewayCapabilities = `["read", "create", "update", "delete", "list"]`

func gatewayCBP(mount, extra string) string {
	stanza := func(path string) string {
		body := "  capabilities = " + gatewayCapabilities + "\n"
		if extra != "" {
			body += extra + "\n"
		}
		return "path \"" + path + "\" {\n" + body + "}\n"
	}
	return stanza(mount+"/gateway*") + stanza(mount+"/role/+/gateway*")
}

func gatewayMCP(mount, rules string) string {
	stanza := func(path string) string {
		return "path \"" + path + "\" {\n" + rules + "\n}\n"
	}
	return stanza(mount+"/gateway*") + stanza(mount+"/role/+/gateway*")
}

func restRouteCBP(route, capabilities, condition string) string {
	stanza := func(path string) string {
		body := "  capabilities = " + capabilities + "\n"
		if condition != "" {
			body += "  condition    = \"" + condition + "\"\n"
		}
		return "path \"" + path + "\" {\n" + body + "}\n"
	}
	return stanza(MountBankAPI+"/gateway/"+route) + stanza(MountBankAPI+"/role/+/gateway/"+route)
}

// Bootstrap returns the writes that build the playground, in order. Order matters:
// the IdP must be serving before the JWT mounts are configured (configuring one
// fetches its JWKS), the rest provider must be mounted before the teller skill
// that requires its skill, and a skill must exist before the role that names it.
func Bootstrap(s Settings) []Step {
	asURL := strings.TrimRight(s.ASURL, "/")
	caData := (&TLS{CAPEM: s.CAPEM}).CAData()

	jwtConfig := map[string]any{
		"jwks_url":     asURL + "/jwks",
		"jwks_ca_pem":  s.CAPEM,
		"bound_issuer": asURL,
	}
	spec := func(audience string, onBehalf bool) map[string]any {
		config := map[string]any{
			"subject_token_source": "warden_identity",
			"assertion_audience":   asURL,
			"audience":             audience,
			"scope":                defaultScope,
		}
		if onBehalf {
			// One assertion carries both: the person as sub, the agent in act.
			config["assertion_user_claims"] = "sub"
		}
		return map[string]any{"type": "oauth_bearer_token", "source": SourceBankAS, "config": config}
	}
	agentRole := func(description, mount, credSpec string, policies []string, skill string) map[string]any {
		role := map[string]any{
			"description":     description,
			"bound_audiences": []string{AudienceAgent},
			"user_claim":      "sub",
			"token_policies":  policies,
			"cred_spec_name":  credSpec,
			"provider_path":   mount + "/",
		}
		if skill != "" {
			role["skill"] = skill
		}
		return role
	}

	return []Step{
		{
			Path: "sys/oidc-issuer/config", Operation: "update",
			Data: map[string]any{"enabled": true, "issuer_url": s.WardenIssuer},
			Note: "Warden's own OIDC issuer signs the assertions the bank's authorization server accepts.",
		},

		// Identities.
		{
			Path: "sys/auth/" + AgentAuthMount, Operation: "create",
			Data: map[string]any{"type": "jwt", "description": "Agent identities, signed by the playground IdP."},
			Note: "Agents present a JWT from the playground IdP.",
		},
		{Path: "auth/" + AgentAuthMount + "/config", Operation: "update", Data: jwtConfig, Note: "Trust the playground IdP's keys."},
		{
			Path: "sys/auth/" + UserAuthMount, Operation: "create",
			Data: map[string]any{"type": "jwt", "description": "User identities, signed by the playground IdP."},
			Note: "People present a JWT from the same IdP, with a different audience.",
		},
		{Path: "auth/" + UserAuthMount + "/config", Operation: "update", Data: jwtConfig, Note: "Trust the playground IdP's keys."},
		{
			Path: "auth/" + UserAuthMount + "/role/" + UserRole, Operation: "create",
			Data: map[string]any{
				"description":     "A person an agent acts for.",
				"bound_audiences": []string{AudienceUser},
				"user_claim":      "sub",
				// Surface may_act so the assistant policy can check it, and the
				// customer tier its withdrawal limit reads.
				"metadata_claims": map[string]any{"/may_act/sub": "may_act_sub", "/tier": "tier"},
			},
			Note: "The person's token exposes which agent may act for them, and their customer tier.",
		},

		// The bank's faces.
		{
			Path: "sys/providers/" + MountBank, Operation: "create",
			Data: map[string]any{"type": "mcp", "description": "The playground bank, as an MCP server."},
			Note: "The bank's MCP face, for an agent on its own account.",
		},
		{
			Path: MountBank + "/config", Operation: "update",
			Data: map[string]any{"mcp_url": s.bankMCPURL(), "ca_data": caData, "auto_auth_path": "auth/" + AgentAuthMount + "/"},
		},
		{
			Path: "sys/providers/" + MountBankMe, Operation: "create",
			Data: map[string]any{"type": "mcp", "description": "The playground bank, as an MCP server, acting for a person."},
			Note: "The same MCP face with a user leg: Authorization carries the person, X-Warden-Agent-Token the agent.",
		},
		{
			Path: MountBankMe + "/config", Operation: "update",
			Data: map[string]any{
				"mcp_url": s.bankMCPURL(), "ca_data": caData, "auto_auth_path": "auth/" + AgentAuthMount + "/",
				"user_auth_path": "auth/" + UserAuthMount + "/", "user_auth_role": UserRole,
			},
		},
		{
			Path: "sys/providers/" + MountBankAPI, Operation: "create",
			Data: map[string]any{"type": "rest", "description": "The playground bank, as an HTTP API."},
			Note: "The bank's REST face. A new rest mount parses request bodies, so policy can read the amount.",
		},
		{
			Path: MountBankAPI + "/config", Operation: "update",
			Data: map[string]any{"base_url": s.bankAPIURL(), "ca_data": caData, "auto_auth_path": "auth/" + AgentAuthMount + "/"},
		},
		{
			Path: "sys/providers/" + MountGitHub, Operation: "create",
			Data: map[string]any{"type": "mcp", "description": "GitHub, as an MCP server."},
			Note: "A real service for the last scenario, reached exactly like the bank's MCP face.",
		},
		{
			// Configuring the mount checks the URL's shape only: the playground
			// still starts offline.
			Path: MountGitHub + "/config", Operation: "update",
			Data: map[string]any{"mcp_url": githubMCPURL, "auto_auth_path": "auth/" + AgentAuthMount + "/"},
		},

		// Credentials: one keyless source, nothing stored.
		{
			Path: "sys/cred/sources/" + SourceBankAS, Operation: "create",
			Data: map[string]any{"type": "token_exchange", "config": map[string]any{
				"token_url":   asURL + "/token",
				"grant":       "rfc8693",
				"client_auth": "none",
				"client_id":   wardenClientID,
				"ca_data":     caData,
			}},
			Note: "Warden proves who is calling with its own assertion; no secret is stored anywhere.",
		},
		{Path: "sys/cred/specs/" + SpecBankAgent, Operation: "create", Data: spec(s.bankMCPURL(), false), Note: "A bank token for the agent itself."},
		{Path: "sys/cred/specs/" + SpecBankOnBehalf, Operation: "create", Data: spec(s.bankMCPURL(), true), Note: "A bank token for a person, with the agent in act."},
		{Path: "sys/cred/specs/" + SpecBankAPIAgent, Operation: "create", Data: spec(s.bankAPIURL(), false), Note: "A bank token for the REST face."},
		{
			// The source holds no secret, so it is created offline; the spec that
			// holds the reader's PAT is theirs to create, in scenario 9.
			Path: "sys/cred/sources/" + SourceGitHub, Operation: "create",
			Data: map[string]any{"type": "github", "config": map[string]any{"github_url": "https://api.github.com"}},
			Note: "Where GitHub tokens come from; the reader adds the PAT.",
		},

		// Policies.
		{Path: "sys/policies/cbp/bank-access", Operation: "create", Data: map[string]any{"policy": policyBankAccess}},
		{Path: "sys/policies/mcp/atm-tools", Operation: "create", Data: map[string]any{"policy": policyATMTools}, Note: "Which tools, and withdrawals of at most 100."},
		{Path: "sys/policies/cbp/assistant-on-behalf", Operation: "create", Data: map[string]any{"policy": policyAssistantOnBehalf}, Note: "Only the agent the person named in may_act."},
		{Path: "sys/policies/mcp/assistant-tools", Operation: "create", Data: map[string]any{"policy": policyAssistantTools}, Note: "Which tools, and withdrawals of at most 100, or 1000 for a premium customer."},
		{Path: "sys/policies/cbp/teller-api", Operation: "create", Data: map[string]any{"policy": policyTellerAPI}, Note: "Routes, and a withdrawal amount read from the body."},
		{Path: "sys/policies/cbp/github-access", Operation: "create", Data: map[string]any{"policy": policyGitHubAccess}},
		{Path: "sys/policies/mcp/github-read", Operation: "create", Data: map[string]any{"policy": policyGitHubRead}, Note: "GitHub's read-only tools."},

		// A skill for the REST role: an HTTP API does not describe itself.
		{
			Path: "sys/skills/" + SkillTeller, Operation: "create",
			Data: map[string]any{
				"description": "Use the playground bank's HTTP API through Warden: balance, deposit, withdraw.",
				"category":    "custom",
				"requires":    []string{"rest"},
				"body":        tellerSkill,
			},
			Note: "The routes, bodies and limits of the bank's HTTP API.",
		},

		// Roles. Each names its provider mount, so discovery returns its url and skill.
		{
			Path: "auth/" + AgentAuthMount + "/role/" + RoleATM, Operation: "create",
			Data: agentRole("Use your own bank account: check the balance and recent transactions, deposit, and withdraw up to 100 at a time.",
				MountBank, SpecBankAgent, []string{"bank-access", "atm-tools"}, ""),
		},
		{
			Path: "auth/" + AgentAuthMount + "/role/" + RoleAssistant, Operation: "create",
			Data: agentRole("Use a person's bank account on their behalf, when they have allowed this agent to act for them: "+
				"check the balance and recent transactions, deposit, and withdraw up to 100 at a time, or 1000 for a premium customer.",
				MountBankMe, SpecBankOnBehalf, []string{"assistant-on-behalf", "assistant-tools"}, ""),
		},
		{
			Path: "auth/" + AgentAuthMount + "/role/" + RoleTeller, Operation: "create",
			Data: agentRole("The bank's HTTP API for your own account: balance, deposit, and withdraw up to 100 at a time.",
				MountBankAPI, SpecBankAPIAgent, []string{"teller-api"}, SkillTeller),
		},
		{
			// Names a spec that does not exist until the reader creates it: a role
			// is stored without checking it, and discovery lists it all the same.
			Path: "auth/" + AgentAuthMount + "/role/" + RoleGitHub, Operation: "create",
			Data: agentRole("Read GitHub repositories, issues and pull requests, with a GitHub token the operator provides.",
				MountGitHub, SpecGitHub, []string{"github-access", "github-read"}, ""),
		},

		// Last, so the log holds the scenarios rather than the setup.
		{
			Path: "sys/audit/" + AuditDevice, Operation: "create",
			Data: map[string]any{"type": "file", "description": "The playground's audit log.", "config": map[string]any{
				"file_path": s.AuditPath,
				// Write each entry at once, so warden dev audit shows a call as
				// soon as it is made. flush_period decodes as nanoseconds.
				"buffer_size":  1,
				"flush_period": int64(200 * time.Millisecond),
			}},
			Note: "Every call from here on is recorded; read it with warden dev audit.",
		},
	}
}
