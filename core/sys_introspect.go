package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"golang.org/x/sync/errgroup"

	authhelper "github.com/stephnangue/warden/auth/helper"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/listener"
	lgr "github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// aggregateIntrospectConcurrency caps per-request goroutines so a namespace
// with many auth mounts cannot spawn unbounded work on a single call.
const aggregateIntrospectConcurrency = 10

// pathIntrospectRoles exposes GET /v1/sys/introspect/roles.
// The endpoint detects the caller's credential format (TLS client cert,
// generic JWT, or Kubernetes SA JWT) and fans out an `introspect/roles`
// call to every auth mount in the caller's namespace whose registered
// TokenType reports a matching CredentialFormat. Results are merged into
// a single roles[] union, with per-mount failures collected into warnings[].
//
// Exact-match filtering is deliberate: a generic JWT never fans out to
// kubernetes mounts (which would burn a TokenReview round-trip the spoke
// cannot satisfy), and a K8s SA token never fans out to generic JWT mounts.
//
// Autonomous agents present their identity vehicle with each request and
// must specify a role so Warden's transparent auth can resolve a cred
// spec. Introspection lets an agent discover which roles it may assume
// without having to distribute role names out-of-band.
func (b *SystemBackend) pathIntrospectRoles() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "introspect/roles",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleIntrospectRoles,
					Summary:  "Discover roles the presented identity can assume",
					Description: "Returns {roles, warnings}. roles[] is the union of " +
						"roles the identity can assume across every auth mount of " +
						"the caller's identity type in the current namespace; each " +
						"entry is {auth_path, name, description}. warnings[] holds " +
						"per-mount failure messages — partial-failure mounts " +
						"surface here rather than failing the whole call. Both " +
						"arrays are sorted and may be empty.",
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: "Roles the presented identity can assume, aggregated across the namespace's auth mounts.",
							MediaType:   "application/json",
							Fields: map[string]*framework.FieldSchema{
								"roles": {
									Type:        framework.TypeSlice,
									Description: "Roles the identity can assume. Each item: {auth_path, name, description}.",
								},
								"warnings": {
									Type:        framework.TypeStringSlice,
									Description: "Per-mount failure messages, one entry per mount that errored. Format: `mount \"<auth-path>\": <error>`. Mounts that don't implement introspection are skipped silently and do NOT appear here.",
								},
							},
						}},
						http.StatusUnauthorized: {{
							Description: "No JWT bearer token or TLS client certificate was presented.",
						}},
					},
				},
			},
			HelpSynopsis:    "Discover roles the presented identity can assume",
			HelpDescription: "Fans out to every auth mount in the current namespace whose registered TokenType matches the caller's credential format (cert, jwt, or k8s_sa_jwt) and returns the union of roles each mount reports the identity can assume.",
		},
	}
}

// aggregatedRole is the per-role payload returned by the system introspection
// endpoint. auth_path is added by the aggregator (not supplied by backends).
type aggregatedRole struct {
	AuthPath    string `json:"auth_path"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

func (b *SystemBackend) handleIntrospectRoles(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	credFormat := detectIntrospectCredentialFormat(req)
	if credFormat == "" {
		return &logical.Response{
			StatusCode: http.StatusUnauthorized,
			Err:        fmt.Errorf("introspection requires a JWT bearer token or TLS client certificate"),
		}, nil
	}

	// Snapshot matching auth-mount entries under the lock, then release
	// before dispatching so that concurrent mount writes are not blocked on
	// our in-process fan-out. The filter asks the registry "what TokenType
	// serves this mount, and does its CredentialFormat exactly match what
	// the caller presented?" — exact-match so a generic JWT never fans out
	// to a kubernetes mount (which would burn a TokenReview round-trip)
	// and vice versa.
	b.core.authLock.RLock()
	authMounts, err := b.core.auth.findAllNamespaceMounts(ctx)
	if err != nil {
		b.core.authLock.RUnlock()
		return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
	}
	matching := make([]*MountEntry, 0, len(authMounts))
	for _, entry := range authMounts {
		tt := b.core.tokenStore.GetTransparentTokenTypeForAuthMethod(entry.Type)
		if tt == nil || tt.CredentialFormat() != credFormat {
			continue
		}
		matching = append(matching, entry)
	}
	b.core.authLock.RUnlock()

	if len(matching) == 0 {
		return b.respondSuccess(map[string]any{
			"roles":    []aggregatedRole{},
			"warnings": []string{},
		}), nil
	}

	// Fan out. Per-mount failures go into warnings[]; they never fail the
	// whole call. A mount that doesn't implement introspect/roles is
	// silently skipped (no warning) so we can roll out per-backend support
	// incrementally.
	type mountResult struct {
		entry *MountEntry
		roles []aggregatedRole
		err   error
	}
	results := make([]mountResult, len(matching))

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(aggregateIntrospectConcurrency)
	for i, entry := range matching {
		i, entry := i, entry
		g.Go(func() error {
			roles, err := b.introspectMount(gctx, req, entry)
			results[i] = mountResult{entry: entry, roles: roles, err: err}
			return nil
		})
	}
	_ = g.Wait()

	aggregated := make([]aggregatedRole, 0)
	warnings := make([]string, 0)
	for _, r := range results {
		if r.err != nil {
			b.logger.Warn("introspect: mount failed",
				lgr.String("mount", r.entry.Path),
				lgr.Err(r.err))
			warnings = append(warnings, fmt.Sprintf("mount %q: %v", r.entry.Path, r.err))
			continue
		}
		aggregated = append(aggregated, r.roles...)
	}
	sort.SliceStable(aggregated, func(i, j int) bool {
		if aggregated[i].AuthPath != aggregated[j].AuthPath {
			return aggregated[i].AuthPath < aggregated[j].AuthPath
		}
		return aggregated[i].Name < aggregated[j].Name
	})

	return b.respondSuccess(map[string]any{
		"roles":    aggregated,
		"warnings": warnings,
	}), nil
}

// introspectMount dispatches an in-process read to a single auth mount's
// introspect/roles path and normalizes the response into aggregatedRole.
// Mounts whose backend does not implement introspection (older auth
// methods, or future ones added before they expose the path) return
// ErrUnsupportedPath and are silently skipped.
func (b *SystemBackend) introspectMount(ctx context.Context, parent *logical.Request, entry *MountEntry) ([]aggregatedRole, error) {
	// Auth mounts are registered in the router under authRoutePrefix +
	// entry.Path (see mountInternalLocked). Build the child request with
	// the full router-visible path.
	childReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      authRoutePrefix + entry.Path + "introspect/roles",
		// Pass through HTTPRequest so the backend can read Authorization
		// header / forwarded client cert via the usual helpers.
		HTTPRequest: parent.HTTPRequest,
		ClientIP:    parent.ClientIP,
	}

	resp, err := b.core.router.Route(ctx, childReq)
	if err != nil {
		if errors.Is(err, sdklogical.ErrUnsupportedPath) {
			return nil, nil
		}
		return nil, err
	}
	if resp == nil || resp.Data == nil {
		return nil, nil
	}
	raw, ok := resp.Data["roles"]
	if !ok {
		return nil, nil
	}

	// Normalize via JSON round-trip: each backend returns a slice of its
	// own package-local struct type (json tagged name/description). The
	// aggregator cannot reference those types without creating a
	// coupling, so we serialize and re-parse into an explicit shape. We
	// unmarshal into an anonymous struct with only the fields we need so
	// that a backend populating extra fields (now or in the future)
	// cannot clobber aggregator-owned fields like auth_path.
	bytes, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("marshal roles: %w", err)
	}
	var parsed []struct {
		Name        string `json:"name"`
		Description string `json:"description,omitempty"`
	}
	if err := json.Unmarshal(bytes, &parsed); err != nil {
		return nil, fmt.Errorf("unmarshal roles: %w", err)
	}
	out := make([]aggregatedRole, len(parsed))
	for i, p := range parsed {
		out[i] = aggregatedRole{
			AuthPath:    entry.Path,
			Name:        p.Name,
			Description: p.Description,
		}
	}
	return out, nil
}

// detectIntrospectCredentialFormat returns the discovery-level credential
// kind the caller presented: "cert" for a forwarded TLS client certificate,
// "k8s_sa_jwt" for a Kubernetes service-account JWT (recognized by its
// mandatory `sub: system:serviceaccount:*` claim), or "jwt" for any other
// JWT bearer token. Returns "" if neither cert nor bearer JWT was sent.
//
// The K8s subtype is detected via an unverified claims parse — signature
// validation happens later, inside the mount that the aggregator fans out
// to. Using the subtype here lets the aggregator route K8s SA tokens only
// to kubernetes mounts and avoid burning a TokenReview round-trip against
// the spoke for a token it cannot authenticate.
func detectIntrospectCredentialFormat(req *logical.Request) string {
	if req.HTTPRequest == nil {
		return ""
	}
	if cert := listener.ForwardedClientCert(req.HTTPRequest.Context()); cert != nil {
		return "cert"
	}
	auth := req.HTTPRequest.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}
	jwt := strings.TrimPrefix(auth, "Bearer ")
	if claims, err := authhelper.ParseJWTClaimsUnverified(jwt); err == nil {
		if sub, _ := claims["sub"].(string); strings.HasPrefix(sub, "system:serviceaccount:") {
			return "k8s_sa_jwt"
		}
	}
	return "jwt"
}
