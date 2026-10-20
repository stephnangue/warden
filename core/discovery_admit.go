package core

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"golang.org/x/sync/errgroup"

	authhelper "github.com/stephnangue/warden/auth/helper"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/listener"
	lgr "github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// Discovery from admissions answers "which roles may this credential assume"
// the way a request would be decided: a role is listed when the auth mount a
// request for it would be admitted through admits the credential, and a
// virtual group grants the role to that admission. That mount (the role's
// target) is the auto_auth_path of the provider at the role's provider_path,
// which is what the gateway admits through; for a role without a usable
// provider, the namespace's auto_auth_path, which non-gateway requests admit
// through; with neither, the role cannot be reached and is left out.
//
// Each distinct target mount admits the credential once, through its internal
// introspect/admit path, and the admission's membership is computed once.
// Nothing here logs in, caches, or writes: the admissions are fresh and are
// dropped when the call returns.
//
// No disclosure: the output names roles only, never a group, a fact, a rule
// or an auth mount. A credential that a target admits but no group matches,
// one for which groups exist but none match, and one in a namespace with no
// groups all yield the same output.

// admittedRole is one role listed by introspectRolesFromAdmissions.
type admittedRole struct {
	Name         string `json:"name"`
	Description  string `json:"description,omitempty"`
	Skill        string `json:"skill,omitempty"`
	ProviderPath string `json:"provider_path,omitempty"`
}

// grantedRole is a role a credential was granted at its target mount.
type grantedRole struct {
	role *logical.Role // the published role: shared, read only
	// viaProvider is set when the target was the role's own provider's auth
	// mount, so the provider's gateway serves the role to this credential.
	viaProvider bool
}

// admissionDiscovery is what discoverFromAdmissions found for one credential.
type admissionDiscovery struct {
	ns        *namespace.Namespace
	granted   []grantedRole                // sorted by role name
	providers map[string]discoveryProvider // the roles' providers, by mount path
	warnings  []string                     // one per target mount that failed; never nil
}

// errDiscoveryNoCredential refuses discovery for a caller that presented no
// credential.
var errDiscoveryNoCredential = errors.New("introspection requires a JWT bearer token or TLS client certificate")

// discoverFromAdmissions finds the roles of the namespace in ctx that the
// credential req carries (its Authorization bearer or forwarded client
// certificate) is granted, each at its target mount.
//
// It reads the namespace's published roles and groups once each and uses one
// now throughout. The target mounts admit concurrently, each on its own
// goroutine writing its own result slot; memberships are computed afterwards
// on the calling goroutine. compute is called directly on each fresh
// admission: never membership, which would cache onto it, and never
// resolveRoleGrant, which projects. A target that fails yields a warning, a
// target whose live naming is human (or that publishes no naming) grants
// nothing, and a credential a target does not admit is silent.
func (c *Core) discoverFromAdmissions(ctx context.Context, req *logical.Request) (*admissionDiscovery, error) {
	if detectIntrospectCredentialFormat(req) == "" {
		return nil, errDiscoveryNoCredential
	}
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	var roles []*logical.Role
	if c.roleStore != nil {
		if nr := c.roleStore.snapshot.Load().byNS[ns.ID]; nr != nil {
			roles = make([]*logical.Role, 0, len(nr.byName))
			for _, e := range nr.byName {
				roles = append(roles, e.role)
			}
			slices.SortFunc(roles, func(a, b *logical.Role) int { return strings.Compare(a.Name, b.Name) })
		}
	}

	providerPaths := make([]string, len(roles))
	for i, r := range roles {
		providerPaths[i] = r.ProviderPath
	}
	providers, err := c.resolveDiscoveryProviders(ctx, providerPaths)
	if err != nil {
		return nil, err
	}
	nsTarget := c.namespaceAuthTarget(ctx, ns)

	// Each role's target mount, and the distinct targets in first-seen order.
	type roleTarget struct {
		mount       string // auth mount path relative to the namespace, without "auth/"
		viaProvider bool
	}
	targetOf := make([]roleTarget, len(roles))
	var targets []string
	for i, r := range roles {
		t := roleTarget{mount: nsTarget}
		if p, ok := providers[r.ProviderPath]; ok && r.ProviderPath != "" && p.authMount != "" {
			t = roleTarget{mount: p.authMount, viaProvider: true}
		}
		targetOf[i] = t
		if t.mount != "" && !slices.Contains(targets, t.mount) {
			targets = append(targets, t.mount)
		}
	}

	// Admit once per target.
	type admitResult struct {
		adm *logical.Admission
		err error
	}
	results := make([]admitResult, len(targets))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(aggregateIntrospectConcurrency)
	for i, mount := range targets {
		g.Go(func() error {
			adm, err := c.admitAt(gctx, req, mount)
			results[i] = admitResult{adm: adm, err: err}
			return nil
		})
	}
	_ = g.Wait()

	gs := c.grantGroups(ns.ID)
	now := time.Now()
	warnings := []string{}
	grants := make(map[string]map[string]logical.GroupGrant, len(targets))
	for i, mount := range targets {
		r := results[i]
		if r.err != nil {
			c.logger.Warn("introspect: mount failed", lgr.String("mount", mount), lgr.Err(r.err))
			warnings = append(warnings, fmt.Sprintf("mount %q: %v", mount, r.err))
			continue
		}
		if r.adm == nil || r.adm.MountPath == "" {
			continue
		}
		n := r.adm.Mount.Load()
		if n == nil || n.Kind == logical.EntityKindHuman {
			// The agent leg never admits through a human mount, and a mount
			// without a naming answers no fact.
			continue
		}
		grants[mount] = compute(r.adm, n, gs, now).Roles
	}

	var granted []grantedRole
	for i, r := range roles {
		t := targetOf[i]
		if _, ok := grants[t.mount][r.Name]; ok && t.mount != "" {
			granted = append(granted, grantedRole{role: r, viaProvider: t.viaProvider})
		}
	}
	return &admissionDiscovery{ns: ns, granted: granted, providers: providers, warnings: warnings}, nil
}

// namespaceAuthTarget returns the auth mount the namespace's auto_auth_path
// resolves to (its path relative to the namespace, without "auth/"), resolved
// verbatim as the non-gateway path resolves it, or "" when none is set or it
// names no auth mount.
func (c *Core) namespaceAuthTarget(ctx context.Context, ns *namespace.Namespace) string {
	path := ns.CustomMetadata["auto_auth_path"]
	if path == "" {
		return ""
	}
	if e := c.router.MatchingMountEntry(ctx, path); e != nil && e.Class == mountClassAuth {
		return e.Path
	}
	return ""
}

// admitAt routes one in-process introspect/admit read, marked Internal, to the
// auth mount at mount (relative to the namespace in ctx, without "auth/") with
// parent's credential, and returns the admission it made with its
// namespace-relative MountPath set, or nil when the mount did not admit the
// credential or does not serve the path. An error is the mount failing.
func (c *Core) admitAt(ctx context.Context, parent *logical.Request, mount string) (*logical.Admission, error) {
	childReq := &logical.Request{
		Operation:   logical.ReadOperation,
		Path:        authRoutePrefix + mount + authhelper.AdmitPattern,
		HTTPRequest: parent.HTTPRequest,
		ClientIP:    parent.ClientIP,
		Internal:    true,
	}
	resp, err := c.router.Route(ctx, childReq)
	if err != nil {
		if errors.Is(err, sdklogical.ErrUnsupportedPath) {
			return nil, nil
		}
		return nil, err
	}
	if resp == nil {
		return nil, nil
	}
	if resp.Err != nil {
		return nil, resp.Err
	}
	admitted, _ := resp.Data[authhelper.AdmittedKey].(bool)
	adm, _ := resp.Data[authhelper.AdmissionKey].(*logical.Admission)
	if !admitted || adm == nil {
		return nil, nil
	}
	c.setAdmissionMountPath(ctx, childReq, adm)
	return adm, nil
}

// introspectRolesFromAdmissions is the sys/introspect/roles handler from
// admissions and groups (see discoverFromAdmissions): {roles, warnings}, each
// role {name, description, skill, provider_path}, sorted by name. No
// credential is a 401, as today. Not yet routed.
func (b *SystemBackend) introspectRolesFromAdmissions(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	d, err := b.core.discoverFromAdmissions(ctx, req)
	if errors.Is(err, errDiscoveryNoCredential) {
		return &logical.Response{StatusCode: http.StatusUnauthorized, Err: err}, nil
	}
	if err != nil {
		return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
	}
	roles := make([]admittedRole, len(d.granted))
	for i, g := range d.granted {
		roles[i] = admittedRole{
			Name:         g.role.Name,
			Description:  g.role.Description,
			Skill:        g.role.Skill,
			ProviderPath: g.role.ProviderPath,
		}
	}
	return b.respondSuccess(map[string]any{
		"roles":    roles,
		"warnings": d.warnings,
	}), nil
}

// resolveDiscoveryFromAdmissionsWith is resolveDiscoveryWith from admissions
// and groups (see discoverFromAdmissions): the roles the credential is
// granted, each with its provider type and URL only when it was granted at
// its own provider's target mount, and its skill URI. Fields that cannot be
// resolved are left out with the same warnings as today. Not yet wired to
// list_roles.
func (c *Core) resolveDiscoveryFromAdmissionsWith(ctx context.Context, skillExists func(name string) bool) ([]mcpRole, []string, error) {
	httpReq := mcpRequestFromContext(ctx)
	if httpReq == nil {
		return nil, nil, fmt.Errorf("internal: request context missing")
	}
	d, err := c.discoverFromAdmissions(ctx, &logical.Request{
		HTTPRequest: httpReq,
		ClientIP:    listener.ClientIP(httpReq),
	})
	if err != nil {
		return nil, nil, err
	}
	warnings := append([]string{}, d.warnings...)
	roles := make([]mcpRole, len(d.granted))
	for i, g := range d.granted {
		r := g.role
		roles[i], warnings = discoveryEntry(d.ns, r.Name, r.Description, r.Skill, r.ProviderPath, d.providers,
			func(discoveryProvider) bool { return g.viaProvider }, skillExists, warnings)
	}
	return roles, warnings, nil
}
