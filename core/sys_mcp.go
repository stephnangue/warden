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
//   - list_roles: the roles the caller's identity can assume, each with its
//     operator-written description (the agent's "menu").
//   - get_skill:  the skill (markdown recipe) named in a role description,
//     teaching the agent how to drive that provider through the gateway.

// mcpServerVersion is the implementation version advertised in the MCP
// initialize handshake. It is informational only; the wire protocol revision
// is negotiated by the SDK independently of this string.
const mcpServerVersion = "1.0.0"

// mcpRequestKey is the private context key under which the middleware stashes
// the inbound *http.Request so tool handlers can recover the caller's
// credentials (Authorization header and forwarded client certificate). The
// SDK does not hand the raw request to tool handlers — it surfaces only
// headers via req.Extra.Header and, notably, not the TLS client certificate —
// so credential detection (detectIntrospectCredentialFormat) needs the
// request threaded through the context.
type mcpRequestKey struct{}

// maxSysMCPBody caps a discovery request body. The two tools this endpoint
// exposes take an empty input and a single skill name, so anything near this
// is already pathological; the cap exists so buffering the body cannot be
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
// eras reach the same two tools.
func (c *Core) MCPServerHandler() http.Handler {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "warden",
		Version: mcpServerVersion,
	}, nil)

	c.registerListRolesTool(server)
	c.registerGetSkillTool(server)

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
		// result and stays open until the client cancels, and a v1.7.0 client
		// opens one during Connect whenever it registers a list-changed
		// handler. Under the listener's deadlines such a stream is severed
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

// mcpRole is a single role projected for the list_roles tool. The aggregator's
// auth_path is deliberately dropped — the agent reads the skill name out of the
// description verbatim and never needs the auth mount path.
type mcpRole struct {
	Name        string `json:"name" jsonschema:"the role name the identity can assume"`
	Description string `json:"description,omitempty" jsonschema:"operator-written description; the skill name is embedded here for the agent to parse and feed to get_skill"`
}

// listRolesInput is the (empty) input for the list_roles tool.
type listRolesInput struct{}

// listRolesOutput is the structured output for the list_roles tool.
type listRolesOutput struct {
	Roles    []mcpRole `json:"roles" jsonschema:"roles the presented identity can assume across the namespace's auth mounts"`
	Warnings []string  `json:"warnings" jsonschema:"per-mount failure messages; may be empty"`
}

// registerListRolesTool wires the list_roles tool onto the MCP server. It
// reuses the sys/introspect/roles aggregator in full — no discovery logic is
// duplicated — and projects each role down to {name, description}.
func (c *Core) registerListRolesTool(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "list_roles",
		Description: "List the roles the presented identity can assume, each with its " +
			"operator-written description. This is the agent's discovery menu: the " +
			"skill name is embedded in each role's description for the agent to read " +
			"and feed to get_skill. Authorizes on the presented identity " +
			"(JWT bearer token or TLS client certificate); no role is required.",
	}, c.handleMCPListRoles)
}

func (c *Core) handleMCPListRoles(ctx context.Context, _ *mcp.CallToolRequest, _ listRolesInput) (*mcp.CallToolResult, listRolesOutput, error) {
	if c.systemBackend == nil {
		return nil, listRolesOutput{}, fmt.Errorf("system backend not initialized")
	}
	httpReq := mcpRequestFromContext(ctx)
	if httpReq == nil {
		return nil, listRolesOutput{}, fmt.Errorf("internal: request context missing")
	}

	lreq := &logical.Request{
		HTTPRequest: httpReq,
		ClientIP:    httpReq.RemoteAddr,
	}

	// FieldData is ignored by the aggregator, so pass nil.
	resp, err := c.systemBackend.handleIntrospectRoles(ctx, lreq, nil)
	if err != nil {
		return nil, listRolesOutput{}, err
	}
	// A no-credential call comes back as a 401 with Err set (mirrors the
	// endpoint). Surface it as an MCP tool error so the model can see it.
	if resp != nil && resp.Err != nil {
		return nil, listRolesOutput{}, resp.Err
	}

	out := listRolesOutput{Roles: []mcpRole{}, Warnings: []string{}}
	if resp != nil && resp.Data != nil {
		if raw, ok := resp.Data["roles"].([]aggregatedRole); ok {
			out.Roles = make([]mcpRole, len(raw))
			for i, r := range raw {
				out.Roles[i] = mcpRole{Name: r.Name, Description: r.Description}
			}
		}
		if w, ok := resp.Data["warnings"].([]string); ok {
			out.Warnings = w
		}
	}

	return nil, out, nil
}

// getSkillInput is the input for the get_skill tool: a skill name. The name is
// the one the operator embeds in a role description (surfaced by list_roles),
// so the agent reads it out of the menu and feeds it back verbatim.
type getSkillInput struct {
	Skill string `json:"skill,omitempty" jsonschema:"the skill name to fetch, as embedded in a role description"`
}

// registerGetSkillTool wires the get_skill tool onto the MCP server. It reuses
// the skill store directly — a skill is fetched by name, no mount resolution.
func (c *Core) registerGetSkillTool(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "get_skill",
		Description: "Fetch an agent skill as markdown by name. The name is the one " +
			"embedded in a role description (list_roles); it identifies the recipe " +
			"teaching the agent how to drive that role through Warden's gateway.",
	}, c.handleMCPGetSkill)
}

func (c *Core) handleMCPGetSkill(ctx context.Context, _ *mcp.CallToolRequest, in getSkillInput) (*mcp.CallToolResult, map[string]any, error) {
	name := strings.TrimSpace(in.Skill)
	if name == "" {
		return nil, nil, fmt.Errorf("skill is required")
	}
	if c.skillStore == nil {
		return nil, nil, fmt.Errorf("skill store not initialized")
	}

	skill, err := c.skillStore.Get(ctx, name)
	if err != nil {
		if errors.Is(err, ErrSkillNotFound) {
			return nil, nil, fmt.Errorf("skill %q not found", name)
		}
		return nil, nil, err
	}

	return nil, skillToMap(skill, false), nil
}
