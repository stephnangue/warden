package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
)

// Warden as an MCP server (discovery interface).
//
// This file makes Warden answer MCP for its own capabilities so an agent can
// discover what it may do before it selects a role and drives a gateway.
//
// The endpoint is always-on at /v1/sys/mcp, a path of the system backend
// served through the request path like every other: authorized by the
// namespace's built-in policies, audited, gated by the MCP policy. It is
// meta-introspection that runs *before* role selection, so it takes no role:
// as an identity path, a call whose answer depends on the caller is admitted
// on the presented identity, exactly like sys/introspect/roles, and one whose
// answer is the same for everyone (initialize, tools/list, ...) runs
// anonymously (admitRoleless).
//
// Two tools are exposed:
//   - list_roles: the roles the caller's identity can assume (the agent's
//     "menu"), each with its description, provider, skill URI and the URL to
//     act under it.
//   - read_skill: the SKILL.md at a role's skill:// URI, teaching the agent
//     how to drive that provider through the gateway.
//
// The same skills are served through the MCP Skills extension
// (sys_mcp_skills.go) for clients that support it.

// mcpServerVersion is the implementation version advertised in the MCP
// initialize handshake. It is informational only; the wire protocol revision
// is negotiated by the SDK independently of this string.
const mcpServerVersion = "1.0.0"

// sysMCPRequestPath is the discovery server's path as the request path sees it
// before routing, relative to the namespace.
const sysMCPRequestPath = "sys/mcp"

// maxSysMCPBody caps a discovery request body. Every request this endpoint
// serves carries at most a skill URI or a cursor, so anything near this is
// already pathological; the cap exists so buffering the body cannot be
// turned into a memory cost.
const maxSysMCPBody = 1 << 20 // 1 MiB

// sysMCPTimeout is this endpoint's answer to a gateway mount's
// listen_timeout: the ceiling on one discovery request once the listener's
// deadlines have been shed.
//
// It bounds what a subscriptions/listen stream may hold. The server announces
// no list as changing, so a client opens one only on purpose, and such a
// stream only ever idles: a short ceiling costs it nothing, and a client that
// wants another reconnects.
const sysMCPTimeout = time.Minute

// maxSysMCPBatch caps the messages in one JSON-RPC batch. Batches survive only
// for clients on protocol revisions before 2025-06-18, and each call in one is
// answered in full, so without a count cap the body cap alone bounds the work:
// a body of small list_roles calls fans out into a response tens of times its
// size. No client batches anywhere near this many discovery calls.
const maxSysMCPBatch = 50

// maxAnonymousListens caps the subscriptions/listen streams callers presenting
// no identity may hold open at once on one system backend. A stream holds a
// goroutine and a connection until sysMCPTimeout, and needs no credential, so
// without a cap anyone who can reach Warden could park them by the thousand.
const maxAnonymousListens = 64

// jsonRPCCodeInvalidRequest is the JSON-RPC 2.0 code for a payload that is
// valid JSON but not an acceptable request.
const jsonRPCCodeInvalidRequest = -32600

// discoveryRequestContext builds the context one discovery request runs under
// outside the request path (the dev playground's self-check): the namespace
// and the raw request threaded through for the handlers, bounded by
// sysMCPTimeout. The caller must call the returned cancel.
func discoveryRequestContext(r *http.Request, ns *namespace.Namespace) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(r.Context(), sysMCPTimeout)
	ctx = namespace.ContextWithNamespace(ctx, ns)
	ctx = withDiscoveryRequest(ctx, r)
	return ctx, cancel
}

// newDiscoveryMCPHandler builds the MCP discovery server served at
// /v1/sys/mcp: the official SDK's Streamable HTTP transport in stateless JSON
// mode, so each POST is a self-contained request/response with no
// Mcp-Session-Id affinity, and a standby node can forward it to the active
// node without session-stickiness concerns.
//
// A modern client needs no handshake to get there — under 2026-07-28 the
// per-request _meta carries what initialize used to negotiate — while a legacy
// client's initialize is still answered, with an ephemeral session, so both
// eras reach the same tools and skills.
//
// It is served through the request path (SystemBackend.handleMCPStream),
// which has authorized and audited the request, admitted its caller, and
// buffered its body before the server sees it.
func (c *Core) newDiscoveryMCPHandler() http.Handler {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "warden",
		Version: mcpServerVersion,
	}, &mcp.ServerOptions{Capabilities: discoveryServerCapabilities()})
	server.AddReceivingMiddleware(discoveryListFilterMiddleware)

	c.registerListRolesTool(server)
	c.registerReadSkillTool(server)
	if err := c.registerSkillsExtension(server); err != nil {
		// Only possible if a method name shadowed a standard MCP method — a
		// programming error. Serving on would declare the extension without
		// implementing it.
		panic(fmt.Sprintf("register MCP skills extension: %v", err))
	}

	return mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return server },
		&mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true},
	)
}

// discoveryListFiltersKey is the context key of the list filters the policy
// layer attached to a discovery request (Request.MCPListFilters).
type discoveryListFiltersKey struct{}

// discoveryListFilter returns the filter for a list method in ctx, or nil.
func discoveryListFilter(ctx context.Context, method string) *logical.MCPListFilter {
	filters, _ := ctx.Value(discoveryListFiltersKey{}).(map[string]*logical.MCPListFilter)
	return filters[strings.ToLower(method)]
}

// discoveryListFilterMiddleware drops from a list answer every item the
// caller's MCP policy would refuse to call, per message, a batch's included:
// what the caller sees listed is what it may call. A request without filters
// passes through untouched.
func discoveryListFilterMiddleware(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		res, err := next(ctx, method, req)
		if err != nil || res == nil {
			return res, err
		}
		f := discoveryListFilter(ctx, method)
		if f == nil {
			return res, err
		}
		switch r := res.(type) {
		case *mcp.ListToolsResult:
			r.Tools = keepListed(r.Tools, f, func(t *mcp.Tool) string { return t.Name })
		case *mcp.ListResourcesResult:
			r.Resources = keepListed(r.Resources, f, func(x *mcp.Resource) string { return x.URI })
		case *skillsListResult:
			r.Skills = keepListed(r.Skills, f, func(e skillEntry) string { return e.URI })
		}
		return res, err
	}
}

// keepListed returns the items f keeps, by the name name reads. The answer's
// own slice is never written: the SDK may build it from shared state.
func keepListed[T any](items []T, f *logical.MCPListFilter, name func(T) string) []T {
	out := make([]T, 0, len(items))
	for _, it := range items {
		if f.Keep(name(it)) {
			out = append(out, it)
		}
	}
	return out
}

// pathMCP serves the discovery server at sys/mcp: a streaming path, so the
// request path buffers and checks its JSON-RPC body before routing, and an
// identity path, so it takes no role (see the backend's PathsSpecial).
func (b *SystemBackend) pathMCP() []*framework.Path {
	op := &framework.PathOperation{
		Callback: b.handleMCPStream,
		Summary:  "Warden's MCP discovery server",
		Description: "MCP Streamable HTTP (stateless, JSON). Tools list_roles and read_skill, " +
			"the skill:// resource template and the Skills extension. Lifecycle calls and " +
			"tools/list need no credential; every other call authorizes on the presented " +
			"JWT bearer token or TLS client certificate, under the namespace's built-in policies.",
	}
	return []*framework.Path{
		{
			Pattern: "mcp",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: op,
				logical.UpdateOperation: op,
				logical.ReadOperation:   op,
				logical.DeleteOperation: op,
			},
			HelpSynopsis: "Warden's MCP discovery server",
			HelpDescription: "Point an MCP client at /v1/sys/mcp, presenting the agent's identity, " +
				"to list the roles it may assume and read their skills.",
		},
	}
}

// handleMCPStream hands a discovery request to the MCP server. The request
// path has already authorized and audited it, admitted its caller (or let it
// run anonymously), buffered its body and shed the listener's deadlines.
//
// The server runs on the request's own context, which carries the discovery
// memo (the admissions the role-less leg made are reused) and the list
// filters, bounded by sysMCPTimeout and ended by a seal or a step-down, so no
// stream outlives the node's active term.
func (b *SystemBackend) handleMCPStream(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	if !req.Streamed || req.HTTPRequest == nil || req.ResponseWriter == nil {
		return logical.ErrorResponse(logical.ErrBadRequest("sys/mcp is served over HTTP only")), nil
	}

	if req.Discovery != nil && req.Discovery.Anonymous && callsMethod(req, "subscriptions/listen") {
		select {
		case b.anonymousListens <- struct{}{}:
			defer func() { <-b.anonymousListens }()
		default:
			return logical.ErrorResponse(logical.ErrServiceUnavailable("too many anonymous notification streams; retry later")), nil
		}
	}

	if len(req.MCPListFilters) > 0 {
		ctx = context.WithValue(ctx, discoveryListFiltersKey{}, req.MCPListFilters)
	}
	ctx, cancel := context.WithTimeout(ctx, sysMCPTimeout)
	defer cancel()
	if active := b.core.activeContext; active != nil {
		stop := context.AfterFunc(active, cancel)
		defer stop()
	}

	b.discoveryMCP().ServeHTTP(req.ResponseWriter, req.HTTPRequest.WithContext(ctx))
	return &logical.Response{Streamed: true}, nil
}

// discoveryMCP returns the backend's MCP server, built on first use.
func (b *SystemBackend) discoveryMCP() http.Handler {
	b.mcpOnce.Do(func() { b.mcpHandler = b.core.newDiscoveryMCPHandler() })
	return b.mcpHandler
}

// callsMethod reports whether req's JSON-RPC body calls method.
func callsMethod(req *logical.Request, method string) bool {
	if req.MCPDescriptor == nil {
		return false
	}
	for i := range req.MCPDescriptor.Calls {
		if strings.EqualFold(req.MCPDescriptor.Calls[i].Method, method) {
			return true
		}
	}
	return false
}

// ShouldEnforceMCPPolicy implements logical.MCPPolicyEnforced: every POST to
// the discovery server answers to the MCP gate, its body capped at
// maxSysMCPBody. A GET or a DELETE carries no JSON-RPC (the server answers it
// 405), so the capability check alone decides it.
func (b *SystemBackend) ShouldEnforceMCPPolicy(req *logical.Request) (bool, int64) {
	return req.HTTPRequest != nil && req.HTTPRequest.Method == http.MethodPost, maxSysMCPBody
}

// MaxMCPBatch implements logical.MCPInProcessServer: the discovery server
// answers every call itself, so it filters lists per call and caps batches.
func (b *SystemBackend) MaxMCPBatch() int { return maxSysMCPBatch }

// RenderGatewayError implements logical.GatewayErrorRenderer for the discovery
// server, the system backend's one streaming path. A body the server cannot
// accept (malformed, oversized, a batch it cannot serve) is a transport fault,
// not an authorization decision: it is answered as the transport answers one,
// a 400 (413 for an oversized body) whose body is a JSON-RPC error with no id,
// so a client fails the call at once instead of reading a refusal it might try
// to authorize its way past. Every other failure keeps Warden's own answer.
func (b *SystemBackend) RenderGatewayError(_ *logical.Request, f *logical.GatewayFailure) *logical.Response {
	var denied *ErrMCPPolicyDenied
	if f == nil || !errors.As(f.Err, &denied) || denied.Decision == nil {
		return nil
	}
	status := http.StatusBadRequest
	message := BuildMCPDenyDescription(denied.Decision)
	switch denied.Decision.RuleType {
	case mcpRuleTypeOversizedBody:
		status = http.StatusRequestEntityTooLarge
	case mcpRuleTypeBatchTooLarge:
		message = fmt.Sprintf("JSON-RPC batch exceeds %d messages", maxSysMCPBatch)
	case mcpRuleTypeMalformedJSONRPC, mcpRuleTypeDuplicateKey, mcpRuleTypeBatchEmpty,
		mcpRuleTypeMalformedParams, mcpRuleTypeBatchUnsupported:
	default:
		return nil
	}
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      nil,
		"error":   map[string]any{"code": jsonRPCCodeInvalidRequest, "message": message},
	})
	if err != nil {
		return nil
	}
	return &logical.Response{
		StatusCode: status,
		Headers:    http.Header{"Content-Type": []string{"application/json"}},
		Body:       body,
	}
}

var (
	_ logical.MCPPolicyEnforced    = (*SystemBackend)(nil)
	_ logical.MCPInProcessServer   = (*SystemBackend)(nil)
	_ logical.GatewayErrorRenderer = (*SystemBackend)(nil)
)

// listRolesInput is the (empty) input for the list_roles tool.
type listRolesInput struct{}

// listRolesOutput is the structured output for the list_roles tool.
type listRolesOutput struct {
	Roles    []mcpRole `json:"roles" jsonschema:"roles the presented identity can assume in this namespace"`
	Warnings []string  `json:"warnings" jsonschema:"auth mounts that could not decide, and role fields that could not be resolved; may be empty"`
}

// registerListRolesTool wires the list_roles tool onto the MCP server. It
// runs the same discovery as sys/introspect/roles and resolves each role's
// provider_path and skill (resolveDiscovery).
func (c *Core) registerListRolesTool(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "list_roles",
		Description: "List the roles the presented identity can assume. This is the agent's " +
			"discovery menu: pick the role whose description fits the task, read its " +
			"skill (a skill:// URI), and the skills that one lists in its frontmatter " +
			"requires, with read_skill or resources/read, then act on Warden's address " +
			"plus the role's url. The descriptions are enough to choose " +
			"a role or to say what you can do; read a skill only for the role you are " +
			"about to use. Authorizes on the presented identity (JWT bearer token or TLS " +
			"client certificate); no role is required.",
	}, c.handleMCPListRoles)
}

func (c *Core) handleMCPListRoles(ctx context.Context, _ *mcp.CallToolRequest, _ listRolesInput) (*mcp.CallToolResult, listRolesOutput, error) {
	roles, warnings, err := c.resolveDiscovery(ctx)
	if err != nil {
		return nil, listRolesOutput{}, err
	}
	if roles == nil {
		roles = []mcpRole{}
	}
	return nil, listRolesOutput{Roles: roles, Warnings: warnings}, nil
}

// readSkillInput is the input for the read_skill tool: a skill URI as
// list_roles returns it.
type readSkillInput struct {
	URI string `json:"uri" jsonschema:"the skill's URI, skill://<name>/SKILL.md, as returned in a role's skill field by list_roles"`
}

// readSkillOutput is the structured output of read_skill.
//
// It carries the whole SKILL.md as well as the text content does. A client may
// read a tool that declares an output schema through its structured output
// alone, and treat the text as a serialisation of it — Claude Code does — so a
// body served only as text never reaches the agent, and the one tool meant to
// hand over instructions hands over a name and a description.
type readSkillOutput struct {
	URI         string           `json:"uri" jsonschema:"the skill's URI"`
	Frontmatter skillFrontmatter `json:"frontmatter" jsonschema:"the SKILL.md frontmatter"`
	Markdown    string           `json:"markdown" jsonschema:"the whole SKILL.md, frontmatter included: the same bytes as resources/read on the URI"`
}

// registerReadSkillTool wires the read_skill tool onto the MCP server: the
// Skills extension's resources/read for clients without it, with the same
// identity-bound visibility (visibleSkill).
func (c *Core) registerReadSkillTool(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "read_skill",
		Description: "Read an agent skill (SKILL.md) by its skill:// URI, as returned in a " +
			"role's skill field by list_roles. The skill teaches how to drive that role's " +
			"provider through Warden. Read it once you have chosen the role, before " +
			"calling it: skills of roles you are not using cost context and teach " +
			"nothing. A skill's requires (in its frontmatter metadata) are part of it: " +
			"read each one before acting. Returns the same bytes as resources/read on the URI.",
	}, c.handleMCPReadSkill)
}

func (c *Core) handleMCPReadSkill(ctx context.Context, _ *mcp.CallToolRequest, in readSkillInput) (*mcp.CallToolResult, readSkillOutput, error) {
	uri := strings.TrimSpace(in.URI)
	if _, err := parseSkillURI(uri); err != nil {
		return nil, readSkillOutput{}, err
	}
	// Same visibility as resources/read: a skill the identity cannot see is
	// answered like one that does not exist.
	skill, err := c.visibleSkill(ctx, uri)
	if err != nil {
		return nil, readSkillOutput{}, err
	}
	if skill == nil {
		return nil, readSkillOutput{}, fmt.Errorf("skill %q not found", uri)
	}

	r, err := c.skillRenders.get(skill)
	if err != nil {
		return nil, readSkillOutput{}, err
	}
	md := string(r.markdown)
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: md}},
	}, readSkillOutput{URI: uri, Frontmatter: frontmatterFor(skill), Markdown: md}, nil
}
