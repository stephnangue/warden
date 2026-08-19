//go:build e2e

package userleg

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// =============================================================================
// RFC 9728 Protected Resource Metadata
// =============================================================================
//
// The document tells a client which authorization server issues the USER
// credential for a mount. Everything here runs against a live cluster because
// the unit tests cover the builder and the handler separately — the seam between
// them, and the routing that gets a request to it, are only exercised here.

type prmDoc struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
	ResourceName           string   `json:"resource_name"`
	ResourceDocumentation  string   `json:"resource_documentation"`
}

func fetchPRM(t *testing.T, port int, mount string) (int, prmDoc, map[string][]string) {
	t.Helper()
	status, body, hdrs := h.DoRequestWithResponseHeaders(t, "GET", h.PRMPath(port, mount), nil, "")
	var doc prmDoc
	if status == 200 {
		if err := json.Unmarshal(body, &doc); err != nil {
			t.Fatalf("metadata is not valid JSON (status %d): %v\n%s", status, err, string(body))
		}
	}
	return status, doc, hdrs
}

// TestPRM_ServesOptedInMount is the shape a client actually consumes.
func TestPRM_ServesOptedInMount(t *testing.T) {
	ensureEnv(t)
	port := leaderPort

	status, doc, hdrs := fetchPRM(t, port, h.UserLegMount)
	if status != 200 {
		t.Fatalf("expected 200 for an opted-in mount, got %d", status)
	}

	want := h.UserLegResourceURL + "/v1/" + h.UserLegMount
	if doc.Resource != want {
		t.Errorf("resource = %q, want %q", doc.Resource, want)
	}

	// Derived from the auth method at user_auth_path — the operator states the
	// issuer once, on the mount, and never restates it here.
	if len(doc.AuthorizationServers) != 1 || doc.AuthorizationServers[0] != h.HydraIssuer {
		t.Errorf("authorization_servers = %v, want [%s]", doc.AuthorizationServers, h.HydraIssuer)
	}

	if len(doc.BearerMethodsSupported) != 1 || doc.BearerMethodsSupported[0] != "header" {
		t.Errorf("bearer_methods_supported = %v, want [header]", doc.BearerMethodsSupported)
	}

	// The operator's mount description, so a consent screen can name what the
	// user is authorizing access to.
	if doc.ResourceName != h.UserLegMountDescription {
		t.Errorf("resource_name = %q, want %q", doc.ResourceName, h.UserLegMountDescription)
	}

	if cc := hdrs["Cache-Control"]; len(cc) == 0 || !strings.Contains(cc[0], "max-age=") {
		t.Errorf("Cache-Control = %v, want a max-age directive", cc)
	}
}

// TestPRM_NotServedWhereItShouldNotBe covers every "no document here" case. All
// are a plain 404: distinguishing them would let an unauthenticated caller probe
// the mount table, and none of the distinctions are actionable by a client.
func TestPRM_NotServedWhereItShouldNotBe(t *testing.T) {
	ensureEnv(t)
	port := leaderPort

	base := h.NodeURL(port) + "/.well-known/oauth-protected-resource"
	for _, tc := range []struct{ name, url string }{
		{"mount without user_auth_path", base + "/v1/vault"},
		{"unknown mount", base + "/v1/does-not-exist"},
		{"bare well-known prefix", base},
		{"prefix with trailing slash only", base + "/"},
		{"agent-only discovery surface", base + "/v1/sys/mcp"},
		{"path missing the /v1/ segment", base + "/vault-user"},
		// Warden is a resource server, never an authorization server.
		{"authorization-server metadata", h.NodeURL(port) + "/.well-known/oauth-authorization-server"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, _ := h.DoRequest(t, "GET", tc.url, nil, "")
			if status != 404 {
				t.Errorf("expected 404, got %d for %s", status, tc.url)
			}
		})
	}
}

// TestPRM_RejectsNonCanonicalPaths guards a cross-mount confusion primitive.
// Go's ServeMux redirects a literal "/../" before the handler, but a
// percent-encoded one arrives decoded and intact — so "/v1/vault-user/%2e%2e/vault"
// would longest-prefix match the opted-in mount while the document echoed a
// `resource` normalizing to a different mount, binding one mount's identifier to
// another's authorization server.
func TestPRM_RejectsNonCanonicalPaths(t *testing.T) {
	ensureEnv(t)
	port := leaderPort

	base := h.NodeURL(port) + "/.well-known/oauth-protected-resource"
	for _, suffix := range []string{
		"/v1/" + h.UserLegMount + "/%2e%2e/vault",
		"/v1/" + h.UserLegMount + "/%2e%2e",
		"/v1/%2e/" + h.UserLegMount,
	} {
		t.Run(suffix, func(t *testing.T) {
			status, body := h.DoRequest(t, "GET", base+suffix, nil, "")
			if status != 404 {
				t.Errorf("expected 404 for a non-canonical path, got %d: %s", status, string(body))
			}
		})
	}
}

// TestPRM_SurvivesProviderHeader is the regression test for the routing order
// that MCP clients actually trip: they commonly set X-Warden-Provider
// connection-wide, and the /v1/ rewrite would otherwise turn a discovery fetch
// into /v1/.well-known/... and 404 it, breaking the bootstrap silently.
func TestPRM_SurvivesProviderHeader(t *testing.T) {
	ensureEnv(t)
	port := leaderPort

	status, body := h.DoRequest(t, "GET", h.PRMPath(port, h.UserLegMount),
		map[string]string{"X-Warden-Provider": h.UserLegMount}, "")
	if status != 200 {
		t.Fatalf("expected 200 with X-Warden-Provider set, got %d: %s", status, string(body))
	}
}

// TestPRM_ServedFromStandby verifies a standby forwards to the active node: the
// document is derived from the live mount table, which only the active node has.
func TestPRM_ServedFromStandby(t *testing.T) {
	ensureEnv(t)
	standby := h.GetStandbyPort(t)
	status, doc, _ := fetchPRM(t, standby, h.UserLegMount)
	if status != 200 {
		t.Fatalf("standby should forward metadata to the active node, got %d", status)
	}
	// Content is node-independent by construction: the resource identifier comes
	// from the configured external base, never the request's host.
	if want := h.UserLegResourceURL + "/v1/" + h.UserLegMount; doc.Resource != want {
		t.Errorf("resource = %q, want %q", doc.Resource, want)
	}
}

// TestPRM_MethodNotAllowed pins GET/HEAD only, with the Allow header RFC 9110
// requires on a 405.
func TestPRM_MethodNotAllowed(t *testing.T) {
	ensureEnv(t)
	port := leaderPort

	status, _, hdrs := h.DoRequestWithResponseHeaders(t, "POST", h.PRMPath(port, h.UserLegMount), nil, "")
	if status != 405 {
		t.Fatalf("expected 405 for POST, got %d", status)
	}
	if allow := hdrs["Allow"]; len(allow) == 0 {
		t.Error("405 must carry an Allow header")
	}
}

// TestPRM_DisableStopsServing verifies resource_url is the master switch, and
// that turning it off leaves mounts otherwise untouched.
func TestPRM_DisableStopsServing(t *testing.T) {
	ensureEnv(t)
	port := leaderPort

	defer restoreEnv(t)

	if status, _, _ := fetchPRM(t, port, h.UserLegMount); status != 200 {
		t.Fatalf("precondition: expected 200, got %d", status)
	}

	h.DisableProtectedResourceMetadata(t, port)
	if status, _, _ := fetchPRM(t, port, h.UserLegMount); status != 404 {
		t.Errorf("expected 404 once resource_url is cleared, got %d", status)
	}

	h.EnableProtectedResourceMetadata(t, port)
	if status, _, _ := fetchPRM(t, port, h.UserLegMount); status != 200 {
		t.Errorf("expected 200 after re-enabling, got %d", status)
	}
}

// TestPRM_UnauthenticatedAccess pins that no credential is needed. A client
// fetches this precisely because it has none yet, so requiring one would make
// the document useless.
func TestPRM_UnauthenticatedAccess(t *testing.T) {
	ensureEnv(t)
	port := leaderPort

	status, body := h.DoRequest(t, "GET", h.PRMPath(port, h.UserLegMount), nil, "")
	if status != 200 {
		t.Fatalf("metadata must be reachable with no credential, got %d: %s", status, string(body))
	}
	if strings.Contains(string(body), "secret") {
		t.Error(fmt.Sprintf("metadata leaked something secret-looking: %s", string(body)))
	}
}
