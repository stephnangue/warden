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

// The standby forwarder recognises the discovery endpoint in every namespace,
// so a forwarded notification stream keeps its deadlines shed there too.
func TestIsSysMCPPath(t *testing.T) {
	for path, want := range map[string]bool{
		"/v1/sys/mcp":           true,
		"/v1/team/sys/mcp":      true,
		"/v1/team/data/sys/mcp": true,
		"/v1/sys/mcpx":          false,
		"/v1/sys/mcp/extra":     false,
		"/v1/sys/roles":         false,
		"/sys/mcp":              false,
	} {
		if got := isSysMCPPath(path); got != want {
			t.Errorf("isSysMCPPath(%q) = %v, want %v", path, got, want)
		}
	}
}
