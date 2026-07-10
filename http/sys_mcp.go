package http

import (
	"net/http"

	"github.com/stephnangue/warden/core"
	"github.com/stephnangue/warden/logger"
)

// handleSysMCP returns the HTTP handler for the /v1/sys/mcp discovery
// interface — Warden answering MCP for its own capabilities (list_roles,
// get_skill).
//
// The MCP server, its tools, and the identity/namespace middleware are built
// in the core package because they reuse core-internal machinery (the
// introspection aggregator, the skill store, the namespace store) that is not
// exported. This wrapper keeps registration consistent with the other
// handleXXX(core, log, …) endpoints and builds the handler once, at
// registration time.
func handleSysMCP(c *core.Core, log *logger.GatedLogger) http.Handler {
	log.Debug("registering MCP discovery interface at /v1/sys/mcp")
	return c.MCPServerHandler()
}
