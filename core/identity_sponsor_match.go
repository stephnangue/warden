package core

import (
	"slices"

	"github.com/stephnangue/warden/logical"
)

// humanTicket reports whether te is a ticket admitting a human: only the
// ticket hook produces an entry of that type, on the request that presented a
// ticket whose seal it checked.
func humanTicket(te *logical.TokenEntry) bool {
	if te == nil || te.Type != logical.TokenTypeTicket || te.Admission == nil {
		return false
	}
	n := te.Admission.Mount.Load()
	return n != nil && n.Kind == logical.EntityKindHuman
}

// callerMatches reports whether a caller whose membership is groups, computed
// in namespace issuingNSID, is a member of the group sp names: that group is
// one of issuingNSID's, still has sp's ID, and is among groups. Groups resolve
// in the namespace that issued the caller's ticket, so a group of a child
// namespace never matches a ticket issued in its parent. Lock-free; it does
// not allocate.
func (c *Core) callerMatches(sp *logical.EntitySponsor, groups []string, issuingNSID string) bool {
	if sp == nil || sp.Namespace != issuingNSID {
		return false
	}
	g := c.grantIndex(issuingNSID).groupsByName[sp.Group]
	return g != nil && g.ID == sp.GroupID && slices.Contains(groups, sp.Group)
}

// requestMembership returns the groups the caller of req is a member of and
// the namespace they were computed in, when the caller is a human ticket
// granted a role: its membership is the role grant's, computed in the
// namespace that issued the ticket. ok is false for any other caller, who is
// a member of no sponsor group.
func requestMembership(req *logical.Request) (groups []string, issuingNSID string, ok bool) {
	te := req.TokenEntry()
	rg := req.RoleGrant()
	if !humanTicket(te) || rg == nil {
		return nil, "", false
	}
	return rg.Groups, te.NamespaceID, true
}

// sponsorActor names the caller te as a sponsor's proposer or accepter: the
// native identity its admission carries, when it has one, and its principal.
func sponsorActor(te *logical.TokenEntry) logical.SponsorActor {
	a := logical.SponsorActor{Principal: te.PrincipalID}
	if adm := te.Admission; adm != nil {
		a.MountAccessor, a.Alias = adm.MountAccessor, adm.AliasName
	}
	if a.Principal == "" {
		// A token with no principal is still named, by its accessor.
		a.Principal = "accessor:" + te.Accessor
	}
	return a
}
