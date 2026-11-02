package core

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// The sponsor surface: the paths on which the humans of an entity's sponsor
// group act on it with no Warden role. They are identity paths (the ticket is
// the whole credential, and the request runs under the built-in policies),
// admitted for a ticket only (isSponsorPath), and each handler decides who
// sponsors what: the caller must be a human whose ticket's membership, computed
// in the namespace that issued it, includes the entity's sponsor group (its
// pending handover's, to accept, or either, to read).
//
// Every refusal is the same response, whatever its cause: no such entity, a
// caller who is not a member, an entity with no sponsor or no handover, one
// changed concurrently, a retired one. A caller with no role cannot learn
// which entities exist.

// sponsorPathPrefix starts every path of the sponsor surface.
const sponsorPathPrefix = "sys/identity/sponsor/"

// isSponsorPath reports whether path, relative to its namespace, is on the
// sponsor surface.
func isSponsorPath(path string) bool { return strings.HasPrefix(path, sponsorPathPrefix) }

// errNoSponsoredAgent is the one refusal of the sponsor surface.
const errNoSponsoredAgent = "no sponsored agent by that name"

// sponsorRefusal is the response to every refused sponsor request.
func sponsorRefusal() *logical.Response {
	return logical.ErrorResponse(logical.ErrForbidden(errNoSponsoredAgent))
}

// testHookSponsorDecided, when set, runs in the accept handler between its
// decision on a read and the store's write, so a test can change the entity
// in between. Nil outside tests, which set it before the request and clear it
// after.
var testHookSponsorDecided func()

// sponsorCaller is the human behind a sponsor request: their ticket's entry,
// and the groups their membership holds in the namespace that issued it.
type sponsorCaller struct {
	te        *logical.TokenEntry
	groups    []string
	issuingNS string
}

// matches reports whether the caller is a member of the group sp names.
func (s *sponsorCaller) matches(c *Core, sp *logical.EntitySponsor) bool {
	return c.callerMatches(sp, s.groups, s.issuingNS)
}

func (b *SystemBackend) pathIdentitySponsor() []*framework.Path {
	entityField := &framework.FieldSchema{Type: framework.TypeString, Description: "Name of the entity", Required: true}
	return []*framework.Path{
		{
			Pattern: "identity/sponsor/" + framework.GenericNameRegex("entity") + "/suspend$",
			Fields:  map[string]*framework.FieldSchema{"entity": entityField},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{Callback: b.handleSponsorSuspend, Summary: "Suspend a sponsored entity"},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.handleSponsorSuspend, Summary: "Suspend a sponsored entity"},
			},
			HelpSynopsis: "Suspend an entity your team sponsors",
			HelpDescription: "A member of the entity's sponsor group suspends it: its requests are refused until an admin " +
				"makes it active again.",
		},
		{
			Pattern: "identity/sponsor/" + framework.GenericNameRegex("entity") + "/handover$",
			Fields: map[string]*framework.FieldSchema{
				"entity": entityField,
				"group":  {Type: framework.TypeString, Description: "The virtual group of humans the entity is handed over to"},
				"namespace": {
					Type: framework.TypeString,
					Description: `The group's namespace: the entity's (the default) or one of its ancestors ` +
						`("/" for the root namespace)`,
				},
				"cancel": {Type: framework.TypeBool, Description: "Cancel the pending handover instead"},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{Callback: b.handleSponsorHandover, Summary: "Hand a sponsored entity over"},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.handleSponsorHandover, Summary: "Hand a sponsored entity over"},
			},
			HelpSynopsis: "Hand an entity your team sponsors over to another group, or cancel a handover",
			HelpDescription: "A member of the entity's sponsor group proposes another group, which a member of it accepts; " +
				"when the caller is a member of both it is accepted at once. With cancel, the pending handover is withdrawn.",
		},
		{
			Pattern: "identity/sponsor/" + framework.GenericNameRegex("entity") + "/accept$",
			Fields:  map[string]*framework.FieldSchema{"entity": entityField},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{Callback: b.handleSponsorAccept, Summary: "Accept a sponsor handover"},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.handleSponsorAccept, Summary: "Accept a sponsor handover"},
			},
			HelpSynopsis: "Accept the sponsorship of an entity handed over to your team",
			HelpDescription: "A member of the pending group makes it the entity's sponsor, replacing the earlier one in the " +
				"same write.",
		},
		{
			Pattern: "identity/sponsor/" + framework.GenericNameRegex("entity") + "$",
			Fields:  map[string]*framework.FieldSchema{"entity": entityField},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{Callback: b.handleSponsorRead, Summary: "Read a sponsored entity"},
			},
			HelpSynopsis:    "Read an entity your team sponsors, or is offered",
			HelpDescription: "A member of the entity's sponsor group, or of its pending handover's, reads the entity.",
		},
	}
}

// sponsorGate does what every sponsor handler does before it decides: it
// resolves the caller, a human ticket with its membership from the request's
// discovery (seeded by the ticket hook, so no auth mount is called and nothing
// is computed again), and the entity. ok is false, with the cause logged at
// debug level only, when either is missing.
func (b *SystemBackend) sponsorGate(ctx context.Context, req *logical.Request, name string) (*logical.Entity, *sponsorCaller, bool) {
	var caller *sponsorCaller
	te := req.TokenEntry()
	cause := "not a human ticket"
	if humanTicket(te) {
		// Read only for a ticket, whose discovery the hook seeded: for any
		// other credential it would admit at the auth mounts.
		d, err := b.core.requestDiscovery(ctx)
		switch {
		case err != nil:
			cause = "no discovery: " + err.Error()
		case d == nil || d.ns == nil || len(d.admitted) != 1 || d.admitted[0].membership == nil:
			cause = "no membership"
		default:
			caller = &sponsorCaller{te: te, groups: d.admitted[0].membership.Groups, issuingNS: d.ns.ID}
		}
	}
	e, _, err := b.core.identityStore.GetEntity(ctx, name)
	if err != nil && caller != nil {
		cause = err.Error()
	}
	if caller == nil || err != nil {
		b.core.logger.Debug("sponsor request refused", logger.String("cause", cause), logger.String("path", req.Path))
		return nil, nil, false
	}
	return e, caller, true
}

// sponsorWriteFailure answers a store write a sponsor handler decided on: the
// refusal for anything the caller's decision no longer holds for (the entity
// changed, is retired or gone, the handover or the group is gone), an
// unavailable store as such, and anything else as an internal error.
func (b *SystemBackend) sponsorWriteFailure(req *logical.Request, err error) *logical.Response {
	switch {
	case errors.Is(err, ErrSponsorChanged), errors.Is(err, ErrSponsorNotFound), errors.Is(err, ErrEntityRetired),
		errors.Is(err, ErrEntityNotFound), errors.Is(err, ErrSponsorGroupNotFound), errors.Is(err, ErrSponsorGroupNotVirtual):
		b.core.logger.Debug("sponsor request refused", logger.String("cause", err.Error()), logger.String("path", req.Path))
		return sponsorRefusal()
	case errors.Is(err, ErrIdentityStoreNotLoaded):
		return logical.ErrorResponse(logical.ErrServiceUnavailable(err.Error()))
	}
	b.core.logger.Error("sponsor write failed", logger.Err(err), logger.String("path", req.Path))
	return logical.ErrorResponse(logical.ErrInternal("sponsor write failed"))
}

// sponsorRespond answers a successful sponsor request with the entity as it
// is now, recording the group the caller acted through for the audit. The
// group is recorded first: a write has already happened, so the audit names
// it even when the entity cannot be read back (deleted since).
func (b *SystemBackend) sponsorRespond(ctx context.Context, req *logical.Request, name string, by *logical.EntitySponsor, warnings ...string) (*logical.Response, error) {
	req.SponsoredBy = "group:" + by.Group
	e, hash, err := b.core.identityStore.GetEntity(ctx, name)
	if err != nil {
		b.core.logger.Warn("sponsor request done, entity not read back", logger.Err(err), logger.String("path", req.Path))
		return logical.ErrorResponse(logical.ErrInternal("the request was applied, but the entity could not be read back")), nil
	}
	data := b.entityToMap(e, hash, b.mountPaths(ctx))
	appendWarnings(data, warnings...)
	return b.respondSuccess(data), nil
}

// handleSponsorRead handles GET sys/identity/sponsor/<entity>: a member of the
// sponsor group, or of the pending handover's, reads the entity, so a team is
// never asked to accept an agent blind.
func (b *SystemBackend) handleSponsorRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("entity").(string)
	e, caller, ok := b.sponsorGate(ctx, req, name)
	if !ok {
		return sponsorRefusal(), nil
	}
	var by *logical.EntitySponsor
	switch {
	case caller.matches(b.core, e.Sponsor):
		by = e.Sponsor
	case caller.matches(b.core, e.PendingSponsor):
		by = e.PendingSponsor
	default:
		return sponsorRefusal(), nil
	}
	return b.sponsorRespond(ctx, req, name, by)
}

// handleSponsorSuspend handles POST sys/identity/sponsor/<entity>/suspend: a
// member of the sponsor group suspends the entity. Nothing on this surface
// makes it active again: that is an admin's write.
func (b *SystemBackend) handleSponsorSuspend(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("entity").(string)
	e, caller, ok := b.sponsorGate(ctx, req, name)
	if !ok || !caller.matches(b.core, e.Sponsor) {
		return sponsorRefusal(), nil
	}
	if err := b.core.identityStore.SetEntityState(ctx, name, logical.EntityStateSuspended, e.Sponsor, ""); err != nil {
		return b.sponsorWriteFailure(req, err), nil
	}
	return b.sponsorRespond(ctx, req, name, e.Sponsor)
}

// handleSponsorHandover handles POST sys/identity/sponsor/<entity>/handover: a
// member of the sponsor group proposes another virtual group of this namespace
// or an ancestor, accepted at once when the caller is a member of it too, or
// with cancel withdraws the pending handover. Removing the sponsor is not
// offered here.
func (b *SystemBackend) handleSponsorHandover(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("entity").(string)
	e, caller, ok := b.sponsorGate(ctx, req, name)
	if !ok || !caller.matches(b.core, e.Sponsor) {
		return sponsorRefusal(), nil
	}
	groupName := d.Get("group").(string)
	if d.Get("cancel").(bool) {
		if groupName != "" {
			return logical.ErrorResponse(logical.ErrBadRequest("cancel and group are exclusive")), nil
		}
		if e.PendingSponsor == nil {
			return logical.ErrorResponse(logical.ErrNotFoundf("entity %q has no pending sponsor handover", name)), nil
		}
		if err := b.core.identityStore.CancelPending(ctx, name, e.PendingSponsor, ""); err != nil {
			return b.sponsorWriteFailure(req, err), nil
		}
		return b.sponsorRespond(ctx, req, name, e.Sponsor)
	}

	if groupName == "" {
		return logical.ErrorResponse(logical.ErrBadRequest("group is required, or cancel")), nil
	}
	ns, err := b.core.sponsorNamespace(ctx, d.Get("namespace").(string))
	if err != nil {
		return logical.ErrorResponse(err), nil
	}
	// One answer for an unknown group and a static one alike: the admin path
	// tells them apart for an admin.
	g := b.core.grantIndex(ns.ID).groupsByName[groupName]
	if g == nil || g.Type != logical.GroupTypeVirtual {
		return logical.ErrorResponse(logical.ErrBadRequest("no such virtual group")), nil
	}
	sp := &logical.EntitySponsor{
		Type:      logical.SponsorTypeGroup,
		Namespace: ns.ID,
		GroupID:   g.ID,
		Group:     g.Name,
		AddedBy:   sponsorActor(caller.te),
		AddedAt:   time.Now().UTC(),
	}
	outcome, err := b.core.identityStore.ProposeSponsor(ctx, name, sp, caller.matches(b.core, sp), e.Sponsor, "")
	if err != nil {
		return b.sponsorWriteFailure(req, err), nil
	}
	var warnings []string
	if outcome == ProposePending {
		warnings = append(warnings, fmt.Sprintf("handover to %s is pending: a member must accept it", qualifiedName(ns.Path, g.Name)))
	}
	warnings = append(warnings, b.core.sponsorGroupWarnings(ctx, ns, g.Group)...)
	return b.sponsorRespond(ctx, req, name, e.Sponsor, warnings...)
}

// handleSponsorAccept handles POST sys/identity/sponsor/<entity>/accept: a
// member of the pending group makes it the sponsor.
func (b *SystemBackend) handleSponsorAccept(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("entity").(string)
	e, caller, ok := b.sponsorGate(ctx, req, name)
	if !ok || !caller.matches(b.core, e.PendingSponsor) {
		return sponsorRefusal(), nil
	}
	if h := testHookSponsorDecided; h != nil {
		h()
	}
	if err := b.core.identityStore.AcceptSponsor(ctx, name, e.PendingSponsor, sponsorActor(caller.te), ""); err != nil {
		return b.sponsorWriteFailure(req, err), nil
	}
	return b.sponsorRespond(ctx, req, name, e.PendingSponsor)
}
