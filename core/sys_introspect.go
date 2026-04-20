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

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/listener"
	lgr "github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// aggregateIntrospectConcurrency caps per-request goroutines so a namespace
// with many auth mounts cannot spawn unbounded work on a single call.
const aggregateIntrospectConcurrency = 10

// pathIntrospectRoles exposes GET /v1/sys/introspect/roles.
// The endpoint detects the caller's credential type (JWT or cert), finds
// every auth mount of that type in the caller's namespace, fans out an
// `introspect/roles` call to each, and aggregates the union.
//
// Autonomous agents present their identity vehicle with each request and
// must specify a role so Warden's transparent auth can resolve a cred
// spec. Introspection lets an agent discover which roles it may specify
// without having to distribute role names out-of-band.
func (b *SystemBackend) pathIntrospectRoles() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "introspect/roles",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleIntrospectRoles,
					Summary:  "Discover roles the presented credential can assume",
				},
			},
			HelpSynopsis:    "Discover roles assumable by the presented credential",
			HelpDescription: "Fans out to every auth mount of the detected credential type (JWT or cert) in the current namespace and returns the union of roles each mount reports as assumable.",
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
	credType := detectIntrospectCredType(req)
	if credType == "" {
		return &logical.Response{
			StatusCode: http.StatusUnauthorized,
			Err:        fmt.Errorf("introspection requires a JWT bearer token or TLS client certificate"),
		}, nil
	}

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
	}

	// Snapshot matching mount entries under the lock, then release before
	// dispatching so that concurrent mount writes are not blocked on our
	// in-process fan-out.
	b.core.mountsLock.RLock()
	matching := make([]*MountEntry, 0)
	for _, entry := range b.core.mounts.Entries {
		if entry.Class != mountClassAuth || entry.NamespaceID != ns.ID || entry.Type != credType {
			continue
		}
		matching = append(matching, entry)
	}
	b.core.mountsLock.RUnlock()

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

// detectIntrospectCredType mirrors the credential-type detection in
// performImplicitAuth: client cert takes precedence, then JWT via
// Authorization: Bearer. Returns "" if neither is present.
func detectIntrospectCredType(req *logical.Request) string {
	if req.HTTPRequest == nil {
		return ""
	}
	if cert := listener.ForwardedClientCert(req.HTTPRequest.Context()); cert != nil {
		return "cert"
	}
	if auth := req.HTTPRequest.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		return "jwt"
	}
	return ""
}
