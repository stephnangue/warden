package core

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"golang.org/x/sync/errgroup"

	authhelper "github.com/stephnangue/warden/auth/helper"
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
// dropped when the call returns. The credential's format is never guessed: a
// target that cannot parse it does not admit it.
//
// No disclosure: the output names roles only, never a group, a fact, a rule
// or an auth mount. A credential that a target admits but no group matches,
// one for which groups exist but none match, and one in a namespace with no
// groups all yield the same output.

// admittedRole is one role listed by sys/introspect/roles.
type admittedRole struct {
	Name         string `json:"name"`
	Description  string `json:"description,omitempty"`
	Skill        string `json:"skill,omitempty"`
	ProviderPath string `json:"provider_path,omitempty"`
}

// admissionDiscovery is what discoverFromAdmissions found for one credential.
type admissionDiscovery struct {
	ns *namespace.Namespace
	// granted are the roles granted at their target mounts, sorted by name:
	// the published roles, shared and read only.
	granted   []*logical.Role
	providers map[string]discoveryProvider // the roles' providers, by mount path
	warnings  []string                     // one per target mount that failed; never nil

	// admitted are the target mounts whose live naming is not human that
	// admitted the credential, sorted by mount, each with its admission and
	// the membership computed for it. The role-less leg names the caller from
	// the first.
	admitted []discoveryAdmitted
	// failed counts the target mounts that could not decide. With no
	// admission, any one failing makes it an outage, not a refusal: the
	// credential may be for the mount that failed.
	failed int
}

// discoveryAdmitted is one target mount that admitted the credential.
type discoveryAdmitted struct {
	mount      string // relative to the namespace, without "auth/"
	adm        *logical.Admission
	membership *logical.Membership
}

// errDiscoveryNoCredential refuses discovery for a caller that presented no
// credential.
var errDiscoveryNoCredential = errors.New("introspection requires a JWT bearer token or TLS client certificate")

// hasDiscoveryCredential reports whether req carries a credential discovery
// can present to an auth mount: a forwarded TLS client certificate, or an
// Authorization bearer, its scheme matched case-insensitively as the gateway
// matches it. It looks at neither: the target mounts verify it.
func hasDiscoveryCredential(req *logical.Request) bool {
	if req.HTTPRequest == nil {
		return false
	}
	if listener.ForwardedClientCert(req.HTTPRequest.Context()) != nil {
		return true
	}
	return logical.StripBearer(req.HTTPRequest.Header.Get("Authorization")) != ""
}

// admitFailureClasses are the classes of the errors an auth mount's admission
// check returns when it cannot decide, in the order they are matched. Each
// class's text is the fixed phrase discovery reports for it.
var admitFailureClasses = []error{
	authhelper.ErrAdmitNotConfigured,
	authhelper.ErrAgentAudiencesRequired,
	authhelper.ErrAdmitNoAudiences,
	authhelper.ErrAdmitNoTrustBundle,
	authhelper.ErrAdmitNoTrustedCA,
	authhelper.ErrAdmitUnverified,
}

// admitFailureGeneric is the phrase reported for a failure of no known class.
const admitFailureGeneric = "could not decide"

// admitFailurePhrase returns the fixed phrase discovery reports for a target
// mount that failed with err: its class's, else admitFailureGeneric. It never
// returns err's own text: discovery answers any bearer holder, and that text
// may name the verifier's host, its status, or its reply.
func admitFailurePhrase(err error) string {
	for _, class := range admitFailureClasses {
		if errors.Is(err, class) {
			return class.Error()
		}
	}
	return admitFailureGeneric
}

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
//
// One call costs at most one admission per distinct target mount, whoever the
// caller is: the credential is not looked at before a target admits it.
func (c *Core) discoverFromAdmissions(ctx context.Context, req *logical.Request) (*admissionDiscovery, error) {
	if !hasDiscoveryCredential(req) {
		return nil, errDiscoveryNoCredential
	}
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	var roles []*logical.Role
	if c.roleStore != nil {
		roles = c.roleStore.snapshot.Load().roles(ns.ID)
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

	// Each role's target mount (auth mount path relative to the namespace,
	// without "auth/"; "" when it has none), and the distinct targets in
	// first-seen order.
	targetOf := make([]string, len(roles))
	var targets []string
	for i, r := range roles {
		t := nsTarget
		if p, ok := providers[r.ProviderPath]; ok && r.ProviderPath != "" && p.authMount != "" {
			t = p.authMount
		}
		targetOf[i] = t
		if t != "" && !slices.Contains(targets, t) {
			targets = append(targets, t)
		}
	}
	// With no role to reach, the namespace's own auth mount still names the
	// caller, so a namespace without roles admits a valid credential (and
	// grants it nothing) rather than refusing it. Only then: with targets,
	// the extra admission would cost a verifier round trip for nothing.
	if len(targets) == 0 && nsTarget != "" {
		targets = append(targets, nsTarget)
	}

	// Admit once per target.
	type admitResult struct {
		adm *logical.Admission
		err error
	}
	results := make([]admitResult, len(targets))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(discoveryAdmitConcurrency)
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
	var admitted []discoveryAdmitted
	failed := 0
	for i, mount := range targets {
		r := results[i]
		if r.err != nil {
			// The log keeps the error verbatim; the caller gets its class.
			c.logger.Warn("introspect: mount failed", lgr.String("mount", mount), lgr.Err(r.err))
			warnings = append(warnings, fmt.Sprintf("mount %q: %s", mount, admitFailurePhrase(r.err)))
			failed++
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
		m := compute(r.adm, n, gs, now)
		grants[mount] = m.Roles
		admitted = append(admitted, discoveryAdmitted{mount: mount, adm: r.adm, membership: m})
	}
	slices.SortFunc(admitted, func(a, b discoveryAdmitted) int { return strings.Compare(a.mount, b.mount) })

	var granted []*logical.Role
	for i, r := range roles {
		if t := targetOf[i]; t != "" {
			if _, ok := grants[t][r.Name]; ok {
				granted = append(granted, r)
			}
		}
	}
	return &admissionDiscovery{
		ns: ns, granted: granted, providers: providers, warnings: warnings,
		admitted: admitted, failed: failed,
	}, nil
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
// credential or does not serve the path. An error is the mount failing or
// unable to decide (unconfigured, no trust anchors, its verifier unreachable),
// which discovery reports as the mount's warning by its class
// (admitFailurePhrase).
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
	c.setAdmissionMount(ctx, childReq, adm)
	return adm, nil
}

// discoveryMemo holds the discovery of one discovery-server request. Every
// handler serving that request shares it (a JSON-RPC batch carries several
// calls, and each skill entry point resolves the visible skills), so a
// request costs at most one admission per distinct target mount however many
// calls it carries. It is computed by the first handler that needs it; the
// others wait for that result.
type discoveryMemo struct {
	once sync.Once
	d    *admissionDiscovery
	err  error
}

// errDiscoveryFailed is the error of a discovery that panicked or returned
// neither a result nor an error. Its text names nothing about the cause, which
// is logged.
var errDiscoveryFailed = errors.New("internal: discovery failed")

// get returns the memoised discovery, running discover on the first call; the
// others wait for that call and share its result. A panic in discover is
// logged with its stack and becomes errDiscoveryFailed, for this call and every
// later one, as the shared calls of package flight turn theirs into errors:
// sync.Once counts a panicking call as done, so without this every later call
// would get neither a discovery nor an error. It never returns (nil, nil).
func (m *discoveryMemo) get(log *lgr.GatedLogger, discover func() (*admissionDiscovery, error)) (*admissionDiscovery, error) {
	m.once.Do(func() {
		m.err = errDiscoveryFailed // stands when discover panics
		defer func() {
			if r := recover(); r != nil {
				log.Error("discovery panicked", lgr.Any("panic", r), lgr.String("stack", string(debug.Stack())))
			}
		}()
		m.d, m.err = discover()
		if m.d == nil && m.err == nil {
			m.err = errDiscoveryFailed
		}
	})
	return m.d, m.err
}

// discoveryMemoKey is the context key of a request's discoveryMemo.
type discoveryMemoKey struct{}

// discoveryRequestKey is the context key under which the inbound
// *http.Request of a discovery request is stashed, so its handlers — the
// discovery server's tools, the skill:// resource and the skills/* methods,
// and the role-less leg of the request path — can recover the caller's
// credentials (Authorization header and forwarded client certificate). The
// MCP SDK does not hand the raw request to handlers — it surfaces only
// headers via req.Extra.Header and, notably, not the TLS client certificate —
// so discovery, which presents the caller's credential to the auth mounts,
// needs the request threaded through the context.
type discoveryRequestKey struct{}

// withDiscoveryRequest stashes r in ctx, with an empty discovery memo: every
// handler serving r, and the role-less leg that admits it, share one
// discovery (requestDiscovery).
func withDiscoveryRequest(ctx context.Context, r *http.Request) context.Context {
	ctx = context.WithValue(ctx, discoveryRequestKey{}, r)
	return context.WithValue(ctx, discoveryMemoKey{}, &discoveryMemo{})
}

// discoveryRequestFromContext recovers the inbound *http.Request stashed by
// withDiscoveryRequest, or nil.
func discoveryRequestFromContext(ctx context.Context) *http.Request {
	r, _ := ctx.Value(discoveryRequestKey{}).(*http.Request)
	return r
}

// requestDiscovery returns the discovery of the discovery request in ctx: the
// memoised one when ctx carries a memo (withDiscoveryRequest puts one there),
// else a fresh one. It never returns (nil, nil).
func (c *Core) requestDiscovery(ctx context.Context) (*admissionDiscovery, error) {
	httpReq := discoveryRequestFromContext(ctx)
	if httpReq == nil {
		return nil, fmt.Errorf("internal: request context missing")
	}
	memo, _ := ctx.Value(discoveryMemoKey{}).(*discoveryMemo)
	if memo == nil {
		memo = &discoveryMemo{}
	}
	return memo.get(c.logger, func() (*admissionDiscovery, error) {
		return c.discoverFromAdmissions(ctx, &logical.Request{
			HTTPRequest: httpReq,
			ClientIP:    listener.ClientIP(httpReq),
		})
	})
}

// resolveDiscoveryWith resolves the discovery of the request in ctx for
// list_roles: the roles the credential is granted, each with its provider
// type and URL when it was granted at its own provider's auth mount, and its
// skill URI, with skillExists answering whether a skill exists. Fields that
// cannot be resolved are left out, with a warning saying why.
func (c *Core) resolveDiscoveryWith(ctx context.Context, skillExists func(name string) bool) ([]mcpRole, []string, error) {
	d, err := c.requestDiscovery(ctx)
	if err != nil {
		return nil, nil, err
	}
	if d == nil {
		return nil, nil, errDiscoveryFailed
	}
	warnings := append([]string{}, d.warnings...)
	roles := make([]mcpRole, len(d.granted))
	for i, r := range d.granted {
		roles[i], warnings = discoveryEntry(d.ns, r, d.providers, skillExists, warnings)
	}
	return roles, warnings, nil
}
