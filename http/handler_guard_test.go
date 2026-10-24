package http

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// infraRoutes are the only routes allowed to bypass the request path: each is
// unauthenticated and unaudited by design. Adding one here is a security
// decision, made on purpose; adding a route to the mux that is neither here
// nor logical fails TestRoutes_NoBypass.
var infraRoutes = map[string]bool{
	// Cluster health, seal state and initialization: answered on standby and
	// sealed nodes, before any credential can be checked.
	"/v1/sys/health":      true,
	"/v1/sys/ready":       true,
	"/v1/sys/leader":      true,
	"/v1/sys/seal-status": true,
	"/v1/sys/init":        true,

	// Origin-root discovery documents, fetched before a client holds a
	// credential.
	oidcDiscoveryPath: true,
	oidcJWKSPath:      true,
	prmPath:           true,
	prmPath + "/":     true,
}

// No route reaches a handler around the request path unless it is a declared
// infrastructure route. A route registered straight on the mux skips
// authentication, policy and audit, as /v1/sys/step-down and /v1/sys/mcp once
// did.
func TestRoutes_NoBypass(t *testing.T) {
	c, log := createTestCoreForHTTP(t)
	props := &HandlerProperties{Core: c, Logger: log}
	fwd := newStandbyForwarder(log, nil, defaultForwardingTimeout)

	seen := map[string]bool{}
	for _, r := range routes(props, fwd) {
		if seen[r.pattern] {
			t.Errorf("route %q registered twice", r.pattern)
		}
		seen[r.pattern] = true
		switch r.kind {
		case routeLogical:
			if !strings.HasPrefix(r.pattern, "/v1/") {
				t.Errorf("logical route %q is outside /v1/", r.pattern)
			}
		case routeInfra:
			if !infraRoutes[r.pattern] {
				t.Errorf("route %q bypasses the request path but is not a declared infrastructure route", r.pattern)
			}
		default:
			t.Errorf("route %q has unknown kind %d", r.pattern, r.kind)
		}
	}
	for p := range infraRoutes {
		if !seen[p] {
			t.Errorf("declared infrastructure route %q is not registered; drop it from infraRoutes", p)
		}
	}
}

// The paths that once had a mux route of their own, and the discovery
// endpoint in a namespace, now resolve to a request-path catch-all.
func TestRoutes_FormerBypassesResolveToRequestPath(t *testing.T) {
	c, log := createTestCoreForHTTP(t)
	props := &HandlerProperties{Core: c, Logger: log}
	mux := newMux(props, newStandbyForwarder(log, nil, defaultForwardingTimeout))

	for target, want := range map[string]string{
		"/v1/sys/mcp":              "/v1/sys/",
		"/v1/sys/step-down":        "/v1/sys/",
		"/v1/sys/introspect/roles": "/v1/sys/",
		"/v1/ns1/sys/mcp":          "/v1/",
		"/v1/ns1/sys/step-down":    "/v1/",
	} {
		_, pattern := mux.Handler(httptest.NewRequest(http.MethodPost, target, nil))
		if pattern != want {
			t.Errorf("%s resolves to %q, want the request path's %q", target, pattern, want)
		}
	}
}
