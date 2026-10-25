// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// The role-less leg. A request on an identity path (logical.Paths.Identity)
// that presents no service token authorizes on the credential it presents,
// before any role is chosen: it is admitted through the namespace's discovery
// targets, the same admissions discovery itself makes, and runs under the
// namespace's built-in policies alone. A role selection is ignored and
// nothing is minted.
//
// The request gets a token entry of its own, built here and never stored or
// cached: an identity token, carrying the ID the gateway's identity token for
// the same credential at the same mount carries, so a caller's discovery and
// gateway requests read as one in the audit. It names no mount accessor, so no
// role grant is resolved on it.

// builtinPolicyNames are the policies a role-less request runs under, by name,
// as its audit entry lists them; buildCBP attaches them by type. Shared by
// every such request: read only.
var builtinPolicyNames = []string{builtinCBPPolicy, builtinMCPPolicy}

// rolelessChallenge is the challenge a refused role-less request carries.
// There is no resource metadata to point at: the discovery endpoints are not
// protected resources, so a client gets no OAuth pointer.
const rolelessChallenge = `Bearer realm="warden"`

// errRolelessNotAdmitted refuses a credential no target mount admitted. It
// names no mount.
var errRolelessNotAdmitted = errors.New("the presented credential is not admitted in this namespace")

// errRolelessUndecided answers a credential no target mount admitted while
// some could not decide (unconfigured, or a verifier unreachable). An outage,
// not a refusal, so a client does not start an authorization flow over it.
// Unlike the refusals, it names the mounts that failed, each by its fixed
// phrase: the same warnings discovery has always shown any bearer holder.
var errRolelessUndecided = errors.New("no auth mount could decide on the presented credential")

// admitRoleless runs the role-less leg for req, a request on an identity path
// in the namespace of ctx that presents no service token, and returns the
// response refusing it, or nil once req carries its token entry. ctx must
// carry the discovery request (withDiscoveryRequest), so the admissions made
// here are the ones its handler reuses.
func (c *Core) admitRoleless(ctx context.Context, req *logical.Request) *logical.Response {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return logical.ErrorResponse(logical.ErrInternal("namespace missing"))
	}

	// A call whose answer is the same for every caller runs anonymously: no
	// credential is checked, so it costs no admission, and a presented one is
	// neither used nor kept. The entry carries only what the policy check
	// needs and claims no token: no type, no ID, no principal.
	if !rolelessNeedsIdentity(req) {
		req.Discovery = &logical.DiscoveryAdmission{
			Anonymous:            true,
			CredentialUnverified: hasDiscoveryCredential(req),
		}
		req.SetTokenEntry(&logical.TokenEntry{
			NamespaceID:   ns.ID,
			NamespacePath: ns.Path,
			CreatedByIP:   req.ClientIP,
			Policies:      builtinPolicyNames,
		})
		req.ClientToken = ""
		return nil
	}

	if !hasDiscoveryCredential(req) {
		return rolelessUnauthorized(errDiscoveryNoCredential)
	}

	d, err := c.requestDiscovery(ctx)
	if err != nil {
		c.logger.Error("role-less admission failed", logger.Err(err), logger.String("path", req.Path))
		return logical.ErrorResponse(logical.ErrInternal("discovery failed"))
	}
	if len(d.admitted) == 0 {
		// A mount that could not decide may be the one this credential is
		// for, so no admission is not a refusal while any failed: say which
		// failed, in the fixed phrases discovery shows any bearer holder.
		if d.failed > 0 {
			return logical.ErrorResponse(logical.ErrServiceUnavailable(
				errRolelessUndecided.Error() + " (" + strings.Join(d.warnings, "; ") + ")"))
		}
		return rolelessUnauthorized(errRolelessNotAdmitted)
	}

	first := d.admitted[0]
	id, err := c.identityTokenIDAt(ctx, req, first.mount)
	if err != nil {
		c.logger.Error("role-less admission: no identity token ID", logger.Err(err), logger.String("mount", first.mount))
		return logical.ErrorResponse(logical.ErrInternal("discovery failed"))
	}

	admittedBy := make([]logical.AdmittedMount, len(d.admitted))
	for i, a := range d.admitted {
		admittedBy[i] = logical.AdmittedMount{Mount: a.mount, PrincipalID: a.adm.PrincipalID}
	}
	req.Discovery = &logical.DiscoveryAdmission{AdmittedBy: admittedBy, RolesGranted: len(d.granted)}

	te := &logical.TokenEntry{
		ID:            id,
		Type:          TypeIdentityToken,
		NamespaceID:   ns.ID,
		NamespacePath: ns.Path,
		PrincipalID:   first.adm.PrincipalID,
		CreatedByIP:   req.ClientIP,
		Policies:      builtinPolicyNames,
	}
	if first.membership != nil {
		// Shared with the membership, read only, as a role grant projects it.
		te.Metadata = first.membership.Metadata
	}
	req.SetTokenEntry(te)
	req.ClientToken = te.ID
	return nil
}

// identityTokenIDAt returns the ID of the identity token the gateway would
// hold for req's credential at the auth mount at mount (relative to the
// namespace in ctx, without "auth/"): the credential keyed as implicit auth
// keys it (transparentCredentialOf), with the mount's accessor.
func (c *Core) identityTokenIDAt(ctx context.Context, req *logical.Request, mount string) (string, error) {
	path := authRoutePrefix + mount
	entry, backend := c.router.MatchingMountEntryAndBackend(ctx, path)
	if entry == nil {
		return "", fmt.Errorf("no auth mount at %q", path)
	}
	formatProvider, ok := backend.(logical.CredentialFormatProvider)
	if !ok {
		return "", fmt.Errorf("auth method %q at %q names no credential format", entry.Type, path)
	}
	tc, err := transparentCredentialOf(req, "", formatProvider.CredentialFormat(), entry.Type, path)
	if err != nil {
		return "", err
	}
	return identityTokenType.ComputeID(identityTokenType.LookupValue(tc.key, entry.Accessor)), nil
}

// discoveryAnonymousMethods are the MCP methods of the discovery server whose
// answer is the same for every caller, besides the lifecycle methods
// (isLifecycleMethod): the tool list (the same two tools for everyone, as the
// built-in policies filter it), the fixed resource template, the server's own
// log level, and the notification stream, which never carries anything since
// neither list ever changes. Every other method answers from the caller's
// identity and needs it; a method missing from here needs it too, so a new
// one is closed until it is classified.
var discoveryAnonymousMethods = map[string]struct{}{
	"tools/list":               {},
	"resources/templates/list": {},
	"logging/setlevel":         {},
	"subscriptions/listen":     {},
}

// discoveryMethodIsAnonymous reports whether an MCP method of the discovery
// server answers the same to every caller.
func discoveryMethodIsAnonymous(method string) bool {
	m := strings.ToLower(method)
	if isLifecycleMethod(m) {
		return true
	}
	_, ok := discoveryAnonymousMethods[m]
	return ok
}

// rolelessNeedsIdentity reports whether req, a request on an identity path,
// needs the caller's identity: whether its answer depends on who asks.
// sys/introspect/roles always does. On the discovery server it is decided per
// call, from the body the extractor parsed before this runs: identity is
// needed when any call needs it. A body with no call (a GET or DELETE, which
// the server answers 405) or one that failed to parse needs none: it costs no
// admission, and the MCP gate refuses a bad body.
func rolelessNeedsIdentity(req *logical.Request) bool {
	if req.Path != sysMCPRequestPath {
		return true
	}
	desc := req.MCPDescriptor
	if desc == nil {
		return true
	}
	if desc.ParseErr != nil || len(desc.Calls) == 0 {
		return false
	}
	for i := range desc.Calls {
		if !discoveryMethodIsAnonymous(desc.Calls[i].Method) {
			return true
		}
	}
	return false
}

// rolelessUnauthorized is the 401 of a refused role-less request.
func rolelessUnauthorized(err error) *logical.Response {
	resp := logical.ErrorResponse(logical.ErrUnauthorized(err.Error()))
	resp.AddHeader("WWW-Authenticate", rolelessChallenge)
	return resp
}
