package core

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// errTicketRefused is the one reason a presented ticket is refused, whatever
// check failed: the server log names the check, the caller learns nothing more.
var errTicketRefused = errors.New("the presented ticket is not valid here")

// errTicketInUserSlot refuses a ticket presented as the user of a protected
// resource: a ticket admits the operator, never a user on whose behalf a call
// is made.
var errTicketInUserSlot = errors.New("a ticket is an operator credential; present it on X-Warden-Token")

// errTicketMisplaced refuses a ticket presented anywhere but X-Warden-Token or
// an Authorization bearer: on X-Warden-Agent-Token, or in a channel a
// provider's extractor reads (an API key header, git's Basic password).
var errTicketMisplaced = errors.New("a ticket is presented on X-Warden-Token or as an Authorization bearer")

// ticketValue returns the ticket req presents, or "", whether it rides the
// Authorization bearer, and whether a ticket rides where none is accepted.
// Only two headers carry one: X-Warden-Token, which wins whatever else the
// request carries, and the Authorization bearer when it is the credential the
// request's extractor took as the caller (not a protected resource's user,
// which captureUserContext refuses).
func ticketValue(req *logical.Request) (value string, bearer, misplaced bool) {
	if req.HTTPRequest == nil {
		return "", false, false
	}
	h := req.HTTPRequest.Header
	if v := h.Get(logical.HeaderWardenToken); v != "" {
		if isTicketValue(v) {
			return v, false, false
		}
		return "", false, false
	}
	if v := logical.StripBearer(h.Get("Authorization")); isTicketValue(v) && v == req.ClientToken {
		return v, true, false
	}
	return "", false, isTicketValue(req.ClientToken) || isTicketValue(h.Get(logical.HeaderWardenAgentToken))
}

// ticketSurface tells admitTicket, once a ticket is presented, the role the
// request asks for, whether it is a provider's surface, and how a refusal is
// rendered there.
type ticketSurface func() (role string, provider bool, refuse func(error) *logical.Response)

// admitTicket admits the ticket req presents, if it presents one, and returns
// the response refusing it, or nil. It runs on every path once the request's
// credential is extracted and before anything else admits it, so a ticket is
// recognised by its prefix alone: no auth mount is called and none has to be
// configured on the path.
//
// A ticket carries no role. On an identity path it takes none: the request
// runs under the built-in policies, as the role-less leg runs any credential
// (admitTicketRoleless), and a refusal is the role-less leg's 401 with its
// challenge. Anywhere else surface names the role it asks for, and
// req.TicketAdmitted lets resolveRoleGrant grant that role. That is the whole
// exception to the refusal of an admission token presented explicitly
// (RoleDeniedExplicitAdmission): a ticket is the credential itself, its seal
// checked here, and nothing else can produce an entry of its type. An
// anonymous call on an identity path decodes nothing.
//
// surface is called only for a ticket. Its refusal renders 401 on a
// provider's gateway or access surface, 403 elsewhere, and 400 for a request
// that selects no role. A request that presents no ticket costs a few header
// reads.
//
// A ticket bound to a key opens only with the request's proof of it
// (checkTicketProof), which signs the body when body is set: on the branch
// where core reads the body whole. A refused proof is a 401 with a DPoP
// challenge on every surface. On a provider's surface a bound ticket also
// selects its role with X-Warden-Role, the one selector there that outranks
// all others and that the proof signs, so a replayed proof cannot reach a
// role through an unsigned one (a SigV4 or Basic credential, default_role).
func (c *Core) admitTicket(ctx context.Context, req *logical.Request, identityPath, body bool, surface ticketSurface) *logical.Response {
	value, bearer, misplaced := ticketValue(req)
	if value == "" && !misplaced {
		return nil
	}
	proof := &ticketProof{req: req, bearer: bearer, body: body}
	if identityPath {
		if !rolelessNeedsIdentity(req) {
			return nil
		}
		if misplaced {
			return rolelessUnauthorized(errTicketMisplaced)
		}
		te, err := c.lookupTicket(ctx, value, proof)
		if err != nil {
			c.logger.Warn("ticket refused", logger.Err(err), logger.String("path", req.Path))
			if resp := ticketProofRefusal(err); resp != nil {
				return resp
			}
			return rolelessUnauthorized(errTicketRefused)
		}
		return c.admitTicketRoleless(ctx, req, te)
	}

	r, provider, refuse := surface()
	if misplaced {
		return refuse(errTicketMisplaced)
	}
	te, err := c.lookupTicket(ctx, value, proof)
	if err != nil {
		c.logger.Warn("ticket refused", logger.Err(err), logger.String("path", req.Path))
		if resp := ticketProofRefusal(err); resp != nil {
			return resp
		}
		return refuse(errTicketRefused)
	}
	if r == "" || provider && te.Admission.Binding != nil && req.HTTPRequest.Header.Get("X-Warden-Role") == "" {
		return refuse(errNoRoleSelected)
	}
	req.TicketAdmitted = true
	req.RequestedRole = r
	req.SetTokenEntry(te)
	req.ClientToken = te.ID
	return nil
}

// operationsTicketSurface is the surface of a request off any provider's
// transparent surface: the role from ?role= then X-Warden-Role, and a refusal
// that is 400 for no role and 403 otherwise.
func operationsTicketSurface(req *logical.Request) ticketSurface {
	return func() (string, bool, func(error) *logical.Response) {
		return operationsRole(req), false, func(err error) *logical.Response {
			if errors.Is(err, errNoRoleSelected) {
				return logical.ErrorResponse(logical.ErrBadRequest(noRoleSelectedOperations))
			}
			return logical.ErrorResponse(logical.ErrForbidden(err.Error()))
		}
	}
}

// providerTicketSurface is the surface of a request on backend's gateway or
// access surface: the role as the provider resolves it (providerRole), and a
// refusal rendered as a failed implicit auth there is, with noRole for a
// request that selects none.
func providerTicketSurface(req *logical.Request, backend logical.Backend, noRole string) ticketSurface {
	return func() (string, bool, func(error) *logical.Response) {
		return providerRole(req, backend), true, func(err error) *logical.Response {
			return providerImplicitAuthFailure(req, err, noRole)
		}
	}
}

// admitTicketRoleless runs the role-less leg for a ticket: the request takes
// the built-in policies of its own namespace, as admitRoleless gives any
// credential, and its discovery is the ticket's (discoveryFromTicket), seeded
// into the request's memo so the identity handlers call no auth mount.
//
// The entry keeps the ticket's ID, type and admission, so audit names the
// person, and names no mount: an entry naming one takes a role per request,
// and an identity path selects none.
func (c *Core) admitTicketRoleless(ctx context.Context, req *logical.Request, te *logical.TokenEntry) *logical.Response {
	ns, err := namespace.FromContext(ctx)
	if err != nil || ns == nil {
		return logical.ErrorResponse(logical.ErrInternal("namespace missing"))
	}
	// The sponsor handlers read the ticket's membership, never a role's
	// provider, so there is nothing to resolve for them.
	d, err := c.discoveryFromTicket(ctx, te, time.Now(), !isSponsorPath(req.Path), req.ProofOfPossession)
	if err != nil {
		c.logger.Error("ticket discovery failed", logger.Err(err), logger.String("path", req.Path))
		return logical.ErrorResponse(logical.ErrInternal("discovery failed"))
	}
	seedDiscovery(ctx, d)

	first := d.admitted[0]
	req.Discovery = &logical.DiscoveryAdmission{
		AdmittedBy:   []logical.AdmittedMount{{Mount: first.mount, PrincipalID: te.PrincipalID, AliasName: first.adm.AliasName}},
		RolesGranted: len(d.granted),
	}
	req.SetTokenEntry(&logical.TokenEntry{
		ID:            te.ID,
		Type:          te.Type,
		NamespaceID:   ns.ID,
		NamespacePath: ns.Path,
		PrincipalID:   te.PrincipalID,
		CreatedByIP:   req.ClientIP,
		ExpireAt:      te.ExpireAt,
		Policies:      builtinPolicyNames,
		// Shared with the membership, read only, as a role grant projects it.
		Metadata:  first.membership.Metadata,
		Admission: te.Admission,
	})
	req.ClientToken = te.ID
	return nil
}

// discoveryFromTicket is the discovery of a ticket: its one admission, at its
// issuing mount, and the roles its membership is granted in the namespace that
// issued it, which is where its roles are resolved on every request
// (resolveRoleGrant reads the token's namespace), whichever namespace the
// request is made in. Every role granted there is assumable through the
// ticket, whatever provider it is used with. The membership is computed afresh
// (compute), as discoverFromAdmissions computes it, never cached onto the
// shared admission. The mount is named with its namespace, since it may not be
// the request's. withProviders resolves the granted roles' providers, which
// only discovery renders. proven says the request proved the ticket's key.
func (c *Core) discoveryFromTicket(ctx context.Context, te *logical.TokenEntry, now time.Time, withProviders, proven bool) (*admissionDiscovery, error) {
	adm := te.Admission
	if adm == nil {
		return nil, errors.New("ticket entry carries no admission")
	}
	me, _, err := c.ticketMount(te.MountAccessor, te.NamespaceID)
	if err != nil {
		return nil, err
	}
	issuing := me.Namespace()
	n := adm.Mount.Load()
	if n == nil {
		return nil, errors.New("issuing mount publishes no naming")
	}
	m := compute(adm, n, c.grantIndex(issuing.ID), now)

	// A human's grants are all virtual (humans are never claimed), so a
	// governed_only role is never listed, and a key_proof_only role is listed
	// only once the key is proved: the next request would refuse either.
	var granted []*logical.Role
	for _, r := range c.namespaceRoles(issuing) {
		if g, ok := m.Roles[r.Name]; ok && r.GrantedThrough(g.Type) && (!r.KeyProofOnly || proven) {
			granted = append(granted, r)
		}
	}
	var providers map[string]discoveryProvider
	if withProviders {
		paths := make([]string, len(granted))
		for i, r := range granted {
			paths[i] = r.ProviderPath
		}
		if providers, err = c.resolveDiscoveryProviders(namespace.ContextWithNamespace(ctx, issuing), paths); err != nil {
			return nil, err
		}
	}
	return &admissionDiscovery{
		ns:        issuing,
		granted:   granted,
		providers: providers,
		warnings:  []string{},
		admitted: []discoveryAdmitted{{
			mount:      issuing.Path + strings.TrimPrefix(adm.MountPath, authRoutePrefix),
			adm:        adm,
			membership: m,
		}},
	}, nil
}

// seedDiscovery makes d the discovery of the request in ctx, so its handlers
// read it rather than admit the credential at any auth mount. It is a no-op
// when ctx carries no memo or the memo already holds a discovery.
func seedDiscovery(ctx context.Context, d *admissionDiscovery) {
	if memo, _ := ctx.Value(discoveryMemoKey{}).(*discoveryMemo); memo != nil {
		memo.once.Do(func() { memo.d = d })
	}
}
