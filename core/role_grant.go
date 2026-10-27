package core

import (
	"errors"
	"fmt"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/logical"
)

// Messages of the refusal of a transparent request that selects no role. The
// gateway path also reads the provider's default_role; transparent operations
// on other paths have no provider, so only the query parameter and the header
// select a role there. An access backend's access paths take the role the same
// way: it has no default_role.
const (
	noRoleSelectedGateway    = "no role selected: put the role in the URL (role/<name>/), set X-Warden-Role, or set the provider's default_role"
	noRoleSelectedOperations = "no role selected: set the role query parameter (?role=<name>) or X-Warden-Role"
	noRoleSelectedAccess     = noRoleSelectedOperations
)

// errNoRoleSelected refuses implicit auth for a request that selects no role,
// before its credential is admitted. Callers answer it with 400 and the
// message of their path.
var errNoRoleSelected = errors.New("no role selected")

// errNoImplicitCredential refuses implicit auth for a request that carries no
// credential at all (no token, no client certificate). It is answered 401
// whether or not a role is selected: the client has to authenticate first,
// and a 401 is what starts that (an OAuth challenge, git's Basic retry).
var errNoImplicitCredential = errors.New("no credential presented")

// errHumanMountOnAgentLeg refuses implicit auth for the agent through a mount
// whose entity kind is human.
var errHumanMountOnAgentLeg = errors.New("agent leg cannot admit through a human mount")

// implicitAuthFailure is the response to a failed implicit auth on the agent
// leg: 400 for a request that selects no role (noRole is the path's message),
// 401 for any other failure.
func implicitAuthFailure(err error, noRole string) *logical.Response {
	if errors.Is(err, errNoRoleSelected) {
		return logical.ErrorResponse(logical.ErrBadRequest(noRole))
	}
	return logical.ErrorResponse(logical.ErrUnauthorized(err.Error()))
}

// providerImplicitAuthFailure is implicitAuthFailure on a provider's
// transparent surface (a gateway path or an access backend's access path),
// noRole being that surface's message. A git smart-HTTP request that selects
// no role is answered 401 rather than 400: git sends the role as the Basic
// username, and only after a challenge, so a 400 would end the exchange where
// a 401 makes git retry with one. Either way a git request gets the Basic
// challenge.
func providerImplicitAuthFailure(req *logical.Request, err error, noRole string) *logical.Response {
	resp := implicitAuthFailure(err, noRole)
	if errors.Is(err, errNoRoleSelected) && isGitSmartHTTP(req) {
		resp = logical.ErrorResponse(logical.ErrUnauthorized(noRole))
	}
	attachGitBasicChallenge(req, resp)
	return resp
}

// takesRoleGrant reports whether te takes its role per request: a token an
// auth mount issued (it names the mount). No token is issued with a role, so
// every token an auth mount issues qualifies; root and other tokens no mount
// issued name no mount, do not qualify, and keep authorizing with the policies
// they were issued.
//
// A qualifying token is an admission token. One without an admission (a token
// reloaded from storage, which has lost it, or one an older version stored
// with a role) qualifies too and is refused. A role written on a per-request
// copy (RoleName) is resolveRoleGrant's own result and is not consulted here.
func takesRoleGrant(te *logical.TokenEntry) bool {
	return te.MountAccessor != ""
}

// resolveRoleGrant decides the role req runs under when its token te takes its
// role per request, and projects that role onto te. The role asked for is
// req.RequestedRole, which only implicit auth sets (with req.Transparent): a
// qualifying token on a request that is not transparent was presented
// explicitly and is refused. For any other token it clears the request's
// grant and leaves te untouched.
//
// te must be this request's own copy of the token entry: the role, its
// policies and spec, and the membership's metadata are written onto it, and
// every consumer downstream (the CBP, CEL, audit, the mint, assertions) reads
// them there. Every path that hands over a token entry hands over a copy.
//
// The grant is computed from the namespace's published groups and roles, read
// once each, and the admission's cached membership under them at now. On a
// grant it sets the grant's GrantedBy; on a refusal, DeniedReason, and te
// keeps no policies and no spec, and buildCBP attaches no built-in policy to
// it, so the request is refused by the CBP even if nothing else refused it. A role edit, a group edit or a mapping edit is seen
// by the next request of a cached admission: nothing here is cached on the
// token.
//
// It is the only writer of the request's grant, which lives inside req by
// value. Lock-free; on a steady membership it allocates nothing, whether it
// grants, refuses, or leaves a token no mount issued alone.
func (c *Core) resolveRoleGrant(req *logical.Request, te *logical.TokenEntry, now time.Time) {
	if !takesRoleGrant(te) {
		req.ClearRoleGrant()
		return
	}

	// Whatever happens below, an admission token runs with the granted role,
	// its policies and spec, or with none.
	te.RoleName = ""
	te.Policies = nil
	te.CredentialSpec = ""

	if !req.Transparent {
		// Only implicit auth, admitting this request's own credential, asks
		// for a role: this admission token arrived as a Warden token.
		req.SetRoleGrant(logical.RoleGrant{DeniedReason: logical.RoleDeniedExplicitAdmission, Groups: noGroups})
		return
	}
	rg := req.SetRoleGrant(logical.RoleGrant{RoleName: req.RequestedRole, Groups: noGroups})

	adm := te.Admission
	if adm == nil {
		rg.DeniedReason = logical.RoleDeniedNoAdmission
		return
	}

	// The membership's metadata map is shared by every request of this
	// credential. TokenEntry.Metadata is read only on every copy, so it is
	// projected as is, not copied.
	m := membership(adm, c.grantIndex(te.NamespaceID), now)
	rg.Groups = m.Groups
	te.Metadata = m.Metadata

	if rg.RoleName == "" {
		rg.DeniedReason = logical.RoleDeniedNoRole
		return
	}
	role := c.grantRole(te.NamespaceID, rg.RoleName)
	if role == nil {
		rg.DeniedReason = logical.RoleDeniedNotFound
		return
	}
	g, ok := m.Roles[role.Name]
	if !ok {
		rg.DeniedReason = logical.RoleDeniedNotAssumable
		return
	}

	rg.Role, rg.GrantedBy = role, g.Label
	te.RoleName = role.Name
	te.Policies = role.Policies
	te.CredentialSpec = role.CredSpecName
}

// withholdRoleGrant is resolveRoleGrant for a check that renders no verdict (a
// login): it records no grant on req, and a token that takes its role per
// request keeps no policies and no spec, as an ungranted one would. te must be
// this request's own copy of the token entry, as for resolveRoleGrant.
func withholdRoleGrant(req *logical.Request, te *logical.TokenEntry) {
	req.ClearRoleGrant()
	if takesRoleGrant(te) {
		te.RoleName = ""
		te.Policies = nil
		te.CredentialSpec = ""
	}
}

// grantIndex returns the published identity index of namespace nsID, its
// groups and entities: emptyNSIndex when the namespace has neither or the
// store is not loaded (a standby, a sealed node), so nothing is granted there.
func (c *Core) grantIndex(nsID string) *nsIndex {
	if c.identityStore == nil {
		return emptyNSIndex
	}
	return c.identityStore.namespaceIndex(nsID)
}

// grantRole returns the published role name of namespace nsID, or nil when
// there is none or the store is not loaded. The role is shared: read only.
func (c *Core) grantRole(nsID, name string) *logical.Role {
	if c.roleStore == nil {
		return nil
	}
	e := c.roleStore.snapshot.Load().lookup(nsID, name)
	if e == nil {
		return nil
	}
	return e.role
}

// testHookSkipRoleVerdict, when set, makes performPolicyChecks skip the role
// verdict, so a test can show a refused grant is refused by the CBP alone.
// False outside tests, which set it before starting any request and clear it
// after the last one returns.
var testHookSkipRoleVerdict bool

// ErrRoleNotGranted refuses a request whose token takes its role per request
// and was granted none. It reads as the refusal's message and unwraps to
// ErrPermissionDenied, so it answers 403 and counts as a denial wherever one is
// recognised.
type ErrRoleNotGranted struct {
	DeniedReason string // one of the logical.RoleDenied constants
	Message      string
}

func (e *ErrRoleNotGranted) Error() string { return e.Message }

func (e *ErrRoleNotGranted) Unwrap() error { return sdklogical.ErrPermissionDenied }

// roleRefusal words the refusal of an ungranted rg for the caller. It names the
// requested role and the admitting mount, both of which the caller chose or
// presented, and never a group, a fact or a selector value.
func roleRefusal(rg *logical.RoleGrant, te *logical.TokenEntry) *ErrRoleNotGranted {
	var msg string
	switch rg.DeniedReason {
	case logical.RoleDeniedNoRole:
		msg = noRoleSelectedGateway
	case logical.RoleDeniedNotFound:
		msg = fmt.Sprintf("role %q not found", rg.RoleName)
	case logical.RoleDeniedNotAssumable:
		var mount string
		if te != nil && te.Admission != nil {
			mount = te.Admission.MountPath
		}
		if mount != "" {
			msg = fmt.Sprintf("role %q is not assumable through %s: no group grants it to this caller", rg.RoleName, mount)
		} else {
			msg = fmt.Sprintf("role %q is not assumable: no group grants it to this caller", rg.RoleName)
		}
	case logical.RoleDeniedExplicitAdmission:
		msg = "admission token presented explicitly; present the credential instead"
	case logical.RoleDeniedNoAdmission:
		msg = "token carries no admission to grant a role from; present the credential instead"
	default:
		msg = "no role granted"
	}
	return &ErrRoleNotGranted{DeniedReason: rg.DeniedReason, Message: msg}
}
