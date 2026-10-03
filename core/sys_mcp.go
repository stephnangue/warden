package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// Warden as an MCP server (discovery interface).
//
// This file makes Warden answer MCP for its own capabilities so an agent can
// discover what it may do before it selects a role and drives a gateway.
//
// The endpoint is always-on at /v1/sys/mcp (wired in http/handler.go). It is
// meta-introspection that runs *before* role selection, so it needs no role
// token; it authorizes on the presented identity alone, exactly like
// sys/introspect/roles and sys/skills reads.
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

// mcpRequestKey is the private context key under which the middleware stashes
// the inbound *http.Request so handlers — tools, the skill:// resource and the
// skills/* methods — can recover the caller's credentials (Authorization
// header and forwarded client certificate). The SDK does not hand the raw
// request to handlers — it surfaces only
// headers via req.Extra.Header and, notably, not the TLS client certificate —
// so credential detection (detectIntrospectCredentialFormat) needs the
// request threaded through the context.
type mcpRequestKey struct{}

// maxSysMCPBody caps a discovery request body. Every request this endpoint
// serves carries at most a skill URI or a cursor, so anything near this is
// already pathological; the cap exists so buffering the body cannot be
// turned into a memory cost.
const maxSysMCPBody = 1 << 20 // 1 MiB

// sysMCPTimeout is this endpoint's answer to a gateway mount's
// listen_timeout: the ceiling on one discovery request once the listener's
// deadlines have been shed.
//
// It has to exist. The endpoint authorizes on the presented identity inside
// each tool handler, so the SDK accepts and holds a subscriptions/listen
// stream before any credential is checked — with no ceiling, unauthenticated
// callers could park goroutines and connections here indefinitely. It is
// generous because a listen stream is meant to live: Warden's tool list never
// changes, so such a stream only ever idles, and a client that wants another
// reconnects.
const sysMCPTimeout = 10 * time.Minute

// errSysMCPBodyTooLarge marks the oversize case so the handler can answer 413
// rather than folding it in with a read failure.
var errSysMCPBodyTooLarge = errors.New("sys/mcp request body too large")

// bufferMCPRequestBody reads r's body into memory and puts it back, so the
// request can be handed to a handler that may hold the response open
// indefinitely without a connection read deadline still being armed. A body
// over the cap is refused rather than truncated — a truncated JSON-RPC body
// would surface as a confusing parse error.
// sysMCPContext builds the context one discovery request runs under: the
// caller's namespace and the raw request threaded through for the tool
// handlers, bounded by sysMCPTimeout. The caller must call the returned
// cancel.
func sysMCPContext(r *http.Request, ns *namespace.Namespace) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(r.Context(), sysMCPTimeout)
	ctx = namespace.ContextWithNamespace(ctx, ns)
	ctx = withMCPRequest(ctx, r)
	return ctx, cancel
}

func bufferMCPRequestBody(r *http.Request) error {
	if r.Body == nil {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxSysMCPBody+1))
	_ = r.Body.Close()
	if err != nil {
		return err
	}
	if len(body) > maxSysMCPBody {
		return errSysMCPBodyTooLarge
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	return nil
}

func withMCPRequest(ctx context.Context, r *http.Request) context.Context {
	return context.WithValue(ctx, mcpRequestKey{}, r)
}

// mcpRequestFromContext recovers the inbound *http.Request stashed by the
// middleware. Returns nil if absent (should not happen for a request routed
// through mcpServerHandler).
func mcpRequestFromContext(ctx context.Context) *http.Request {
	r, _ := ctx.Value(mcpRequestKey{}).(*http.Request)
	return r
}

// mcpServerHandler builds the always-on MCP discovery endpoint served at
// /v1/sys/mcp. It runs the official SDK's Streamable HTTP transport in
// stateless JSON mode: each POST is a self-contained request/response with no
// Mcp-Session-Id affinity, so a standby node can forward it to the active node
// without session-stickiness concerns.
//
// A modern client needs no handshake to get there — under 2026-07-28 the
// per-request _meta carries what initialize used to negotiate — while a legacy
// client's initialize is still answered, with an ephemeral session, so both
// eras reach the same tools and skills.
func (c *Core) MCPServerHandler() http.Handler {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "warden",
		Version: mcpServerVersion,
	}, &mcp.ServerOptions{Capabilities: discoveryServerCapabilities()})

	c.registerListRolesTool(server)
	c.registerReadSkillTool(server)
	if err := c.registerSkillsExtension(server); err != nil {
		// Only possible if a method name shadowed a standard MCP method — a
		// programming error. Serving on would declare the extension without
		// implementing it.
		panic(fmt.Sprintf("register MCP skills extension: %v", err))
	}

	streamable := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return server },
		&mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true},
	)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reject on a sealed node. This route bypasses HandleRequest (which
		// guards seal state before any namespace access), so without this
		// check a POST to a sealed node would dereference c.namespaceStore
		// after seal has niled it (teardownNamespaceStore). Standby is already
		// handled upstream: the route is not in standbyAllowedPaths, so
		// wrapGenericHandler forwards it to the active node.
		if c.Sealed() {
			http.Error(w, "Warden is sealed", http.StatusServiceUnavailable)
			return
		}

		// Resolve the caller's namespace the same way transparent callers
		// select one: the X-Warden-Namespace header. One fixed route serves
		// every namespace; a root caller omits the header, a caller in
		// team-data sends "team-data". The tool handlers' fan-out and
		// mount lookups then resolve in this namespace.
		nsHeader := r.Header.Get("X-Warden-Namespace")
		ns, _ := c.namespaceStore.ResolveNamespaceFromRequest(nsHeader, "sys/mcp")
		if ns == nil {
			http.Error(w, "namespace not found", http.StatusNotFound)
			return
		}

		// Thread the namespace into the context (used by the tool handlers'
		// reused core logic) and stash the raw request (used for credential
		// detection). The request's own context already carries the
		// Authorization header and the forwarded client cert — the listener's
		// certForwardingMiddleware injected the latter before routing — so
		// stashing r preserves both for detectIntrospectCredentialFormat.
		// JSONResponse does not make every response here a buffered one: the
		// SDK forces SSE for subscriptions/listen, which has no synchronous
		// result and stays open until the client cancels, and an SDK client
		// opens one during Connect whenever it registers a list-changed
		// handler the server's capabilities announce (tools here). Under the
		// listener's deadlines such a stream is severed
		// seconds in — and not only by the write deadline: once the body is
		// drained, an armed read deadline cancels the request context, which
		// is exactly what the SDK blocks on.
		//
		// The deadlines cannot be shed reactively, on seeing the response
		// declare itself an event stream, because the SDK sets that
		// Content-Type on the header map and then blocks without writing a
		// byte. So read the body first — under the deadlines the listener
		// armed, which is what bounds a dribbling client — and shed them
		// before handing over to a handler that may never return.
		if err := bufferMCPRequestBody(r); err != nil {
			if errors.Is(err, errSysMCPBodyTooLarge) {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "could not read request body", http.StatusBadRequest)
			return
		}
		if err := logical.ClearStreamDeadlines(w); err != nil {
			c.logger.Warn("could not clear connection deadlines for sys/mcp", logger.Err(err))
		}

		ctx, cancel := sysMCPContext(r, ns)
		defer cancel()
		streamable.ServeHTTP(w, r.WithContext(ctx))
	})
}

// listRolesInput is the (empty) input for the list_roles tool.
type listRolesInput struct{}

// listRolesOutput is the structured output for the list_roles tool.
type listRolesOutput struct {
	Roles    []mcpRole `json:"roles" jsonschema:"roles the presented identity can assume across the namespace's auth mounts"`
	Warnings []string  `json:"warnings" jsonschema:"per-mount failure messages; may be empty"`
}

// registerListRolesTool wires the list_roles tool onto the MCP server. It
// reuses the sys/introspect/roles aggregator in full and resolves each role's
// provider_path and skill (resolveDiscovery).
func (c *Core) registerListRolesTool(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "list_roles",
		Description: "List the roles the presented identity can assume. This is the agent's " +
			"discovery menu: pick the role whose description fits the task, read its " +
			"skill (a skill:// URI) with read_skill or resources/read, then act on " +
			"Warden's address plus the role's url. The descriptions are enough to choose " +
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
			"nothing. Returns the same bytes as resources/read on the URI.",
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
