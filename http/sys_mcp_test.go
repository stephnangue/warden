package http

import "testing"

// TestSysMCP_NotStandbyAllowed pins that the MCP discovery route is NOT served
// directly on standby nodes. It reads live mount/skill/introspection state, so
// standby nodes must forward it to the active node. If someone adds it to
// standbyAllowedPaths, standby callers would get stale or empty results.
func TestSysMCP_NotStandbyAllowed(t *testing.T) {
	if standbyAllowedPaths["/v1/sys/mcp"] {
		t.Fatal("/v1/sys/mcp must not be in standbyAllowedPaths: it reads live state and must forward to the active node")
	}
}
