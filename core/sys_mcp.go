package core

import (
	"context"
	"fmt"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/stephnangue/warden/internal/namespace"
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
//   - get_skill:  (added in a later change) the provider-type recipe teaching
//     the agent how to drive a provider through the gateway.

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
// without session-stickiness concerns. The SDK still performs the full
// initialize + protocol-version negotiation on every call.
func (c *Core) MCPServerHandler() http.Handler {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "warden",
		Version: mcpServerVersion,
	}, nil)

	c.registerListRolesTool(server)

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
		ctx := namespace.ContextWithNamespace(r.Context(), ns)
		ctx = withMCPRequest(ctx, r)
		streamable.ServeHTTP(w, r.WithContext(ctx))
	})
}

// mcpRole is a single role projected for the list_roles tool. The aggregator's
// auth_path is deliberately dropped — the agent reads the provider path out of
// the description verbatim and never needs the auth mount path.
type mcpRole struct {
	Name        string `json:"name" jsonschema:"the role name the identity can assume"`
	Description string `json:"description,omitempty" jsonschema:"operator-written description; the provider mount path is embedded here for the agent to parse"`
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
			"provider mount path is embedded in each role's description for the agent " +
			"to read and feed to get_skill. Authorizes on the presented identity " +
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
