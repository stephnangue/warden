package core

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
)

// ProtectedResourceMetadata is the RFC 9728 document describing one mount as an
// OAuth protected resource: what it is called, and which authorization server a
// client should obtain a user credential from.
//
// Warden is a resource server, never an authorization server — it publishes this
// so clients go to the operator's identity provider, and deliberately does not
// serve RFC 8414 authorization-server metadata.
type ProtectedResourceMetadata struct {
	// Resource is the canonical identifier of this mount: the external base URL
	// joined with the mount's API path.
	Resource string `json:"resource"`

	// AuthorizationServers names the issuer(s) a client runs OAuth against.
	AuthorizationServers []string `json:"authorization_servers,omitempty"`

	// BearerMethodsSupported is always ["header"]: the user credential rides
	// Authorization. Warden reads it from no other slot on a non-git mount, and
	// query/body delivery is never accepted.
	BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty"`

	// ResourceName is the operator's own description of the mount, so a consent
	// screen can say what the user is authorizing access to.
	ResourceName string `json:"resource_name,omitempty"`

	// ResourceDocumentation is an optional human-facing URL.
	ResourceDocumentation string `json:"resource_documentation,omitempty"`
}

// ErrNotProtectedResource signals that no metadata may be served for a path —
// the feature is off, the path names no mount, the mount is not opted in, or no
// authorization server could be derived. Every one of those is reported to a
// client as a plain 404: which of them applies is operator-facing detail, and
// distinguishing them would let an unauthenticated caller probe the mount table.
var ErrNotProtectedResource = fmt.Errorf("not a protected resource")

// ProtectedResourceMetadata builds the RFC 9728 document for the resource named
// by suffix — the request path after the well-known prefix, e.g.
// "/v1/team-a/github". Returns ErrNotProtectedResource when none should be
// served.
//
// Namespace and mount are resolved per request rather than cached: the document
// is derived from live mount configuration, and the config load at unseal
// happens before mounts exist.
func (c *Core) ProtectedResourceMetadata(ctx context.Context, suffix string) ([]byte, time.Duration, error) {
	cfg, err := c.protectedResourceConfig(ctx)
	if err != nil {
		return nil, 0, err
	}
	if !cfg.enabled() {
		return nil, 0, ErrNotProtectedResource
	}

	nsCtx, mountPath, err := c.resolveProtectedResourcePath(suffix)
	if err != nil {
		return nil, 0, err
	}

	// MatchingMountEntry first, and it does not log on a miss — unlike
	// MatchingBackend. This endpoint is unauthenticated, so a lookup that logs
	// per miss would be a log-flooding vector.
	entry := c.router.MatchingMountEntry(nsCtx, mountPath)
	if entry == nil {
		return nil, 0, ErrNotProtectedResource
	}

	backend := c.router.MatchingBackend(nsCtx, mountPath)
	if backend == nil {
		return nil, 0, ErrNotProtectedResource
	}

	// Opt-in is the mount's own user_auth_path — the same switch that decides
	// whether Authorization carries a user on this mount. A mount that cannot
	// validate a user must not advertise that it wants one.
	userAuthPath, _ := c.resolveUserAuthConfig(nsCtx, backend)
	if userAuthPath == "" {
		return nil, 0, ErrNotProtectedResource
	}

	servers, err := c.authorizationServersFor(nsCtx, cfg, userAuthPath)
	if err != nil {
		return nil, 0, err
	}

	doc := &ProtectedResourceMetadata{
		Resource:               joinResourceURL(cfg.ResourceURL, suffix),
		AuthorizationServers:   servers,
		BearerMethodsSupported: []string{"header"},
		ResourceName:           entry.Description,
		ResourceDocumentation:  cfg.ResourceDocumentation,
	}
	if doc.ResourceName == "" {
		doc.ResourceName = strings.TrimSuffix(entry.Path, "/")
	}
	body, err := json.Marshal(doc)
	if err != nil {
		return nil, 0, err
	}
	// The cache lifetime comes from the same config generation that produced the
	// document, so a concurrent write cannot make the two disagree.
	return body, cfg.cacheTTL(), nil
}

// resolveProtectedResourcePath splits a "/v1/<ns>/<mount>" suffix into a
// namespace-bearing context and the mount path within that namespace.
func (c *Core) resolveProtectedResourcePath(suffix string) (context.Context, string, error) {
	// The suffix must already be canonical. Go's ServeMux redirects a literal
	// "/../" before the handler runs, but a percent-encoded one ("%2e%2e")
	// arrives decoded and intact — so "/v1/github/../plain" would longest-prefix
	// match the github mount while the document echoed a `resource` that
	// normalizes to /v1/plain. That would bind one mount's identifier to another
	// mount's authorization server: a token-confusion primitive for any client
	// that normalizes `resource` before comparing it. Require canonical form
	// rather than cleaning, so the identifier we publish is always the one that
	// was asked for.
	if suffix != path.Clean(suffix) {
		return nil, "", ErrNotProtectedResource
	}

	// The suffix must name an API resource: "/v1/<ns...>/<mount>". Checked as a
	// literal prefix rather than by trimming, so a path that merely happens to
	// survive a trim (e.g. "/sys/mcp") is not mistaken for one.
	const apiPrefix = "/v1/"
	if !strings.HasPrefix(suffix, apiPrefix) {
		return nil, "", ErrNotProtectedResource
	}
	rel := suffix[len(apiPrefix):]
	if rel == "" {
		return nil, "", ErrNotProtectedResource
	}

	if c.namespaceStore == nil {
		return nil, "", ErrNotProtectedResource
	}
	ns, mountPath := c.namespaceStore.ResolveNamespaceFromRequest("", rel)
	if ns == nil || mountPath == "" {
		return nil, "", ErrNotProtectedResource
	}

	// MatchingMountEntry does a longest-prefix match against router keys, which
	// carry a trailing slash. A bare mount name would otherwise miss.
	if !strings.HasSuffix(mountPath, "/") {
		mountPath += "/"
	}
	return namespace.ContextWithNamespace(context.Background(), ns), mountPath, nil
}

// authorizationServersFor returns the issuer(s) to advertise: the global
// override when set, else whatever the mount's user auth method can name.
func (c *Core) authorizationServersFor(ctx context.Context, cfg *protectedResourceConfig, userAuthPath string) ([]string, error) {
	if len(cfg.AuthorizationServers) > 0 {
		return cfg.AuthorizationServers, nil
	}

	// Check the mount exists before MatchingBackend, which logs an error on a
	// miss. A dangling user_auth_path would otherwise let anonymous fetches
	// write an error line each.
	authPath := normalizeAuthPath(userAuthPath)
	if c.router.MatchingMountEntry(ctx, authPath) == nil {
		return nil, ErrNotProtectedResource
	}
	authBackend := c.router.MatchingBackend(ctx, authPath)
	if authBackend == nil {
		return nil, ErrNotProtectedResource
	}
	provider, ok := authBackend.(logical.AuthorizationServerProvider)
	if !ok {
		return nil, ErrNotProtectedResource
	}
	issuer, ok := provider.AuthorizationServerURL()
	if !ok || issuer == "" {
		// A mount that authenticates users without knowing an issuer (static
		// keys, bare JWKS) or an auth method with no OAuth notion at all
		// (spiffe, kubernetes). There is nothing a client could discover.
		return nil, ErrNotProtectedResource
	}
	// Hold a derived issuer to the same standard as an operator-supplied one: a
	// client redirects a user's browser there, and the auth mount validates its
	// discovery URL for reachability, not for scheme. Advertising a plaintext
	// authorization server would be worse than advertising none.
	if err := validateExternalHTTPSURL(issuer, "authorization_servers",
		"a client redirects a user's browser there"); err != nil {
		return nil, ErrNotProtectedResource
	}
	return []string{issuer}, nil
}

// normalizeAuthPath renders a configured user_auth_path as a router key.
// Operators write it either way ("auth/user-jwt/" or "auth/user-jwt").
func normalizeAuthPath(p string) string {
	if !strings.HasSuffix(p, "/") {
		p += "/"
	}
	return p
}

// joinResourceURL concatenates the external base with the resource path,
// collapsing the slash between them so a base written with or without a
// trailing slash yields the same identifier. The identifier is compared
// literally by clients, so it must be stable.
func joinResourceURL(base, suffix string) string {
	return strings.TrimSuffix(base, "/") + "/" + strings.TrimPrefix(suffix, "/")
}

// protectedResourceConfig loads the configuration from its barrier view.
func (c *Core) protectedResourceConfig(ctx context.Context) (*protectedResourceConfig, error) {
	view := NewBarrierView(c.barrier, protectedResourceStorePrefix)
	return loadProtectedResourceConfig(ctx, view)
}
