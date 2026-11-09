package core

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/go-secure-stdlib/parseutil"

	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// forceKey is the request field that overrides an identity guard. It is taken
// out of the request before routing, so the backend never sees it.
const forceKey = "force"

// takeForce removes force from req.Data and reports whether it was true.
func takeForce(req *logical.Request) bool {
	raw, ok := req.Data[forceKey]
	if !ok {
		return false
	}
	delete(req.Data, forceKey)
	force, err := parseutil.ParseBool(raw)
	return err == nil && force
}

// refuseAliasChange guards a write to an auth mount's config that changes how
// the mount derives aliases (its entity_kind, alias_name_source, or the facts
// mapping behind the alias fact) while native identities are claimed on the
// mount: those identities were derived the old way, so every claim on the
// mount would stop matching the credentials it was made for. The write is
// refused unless it carries force=true, which is logged; force is taken out
// of every config write either way, so the backend never sees it. A write
// that derives aliases as before passes, and so does one the backend refuses
// anyway. Auth backends cannot consult the identity store, so core checks
// before routing; the caller calls it for non-streaming requests on auth
// paths only, after the token check. A forced change returns a warning for
// the caller to put on the write's response.
func (c *Core) refuseAliasChange(ctx context.Context, req *logical.Request) (warning string, err error) {
	// The cheap tests first: every other auth request (logins, discovery's
	// admissions) leaves here without a mount lookup.
	if req.Operation != logical.CreateOperation && req.Operation != logical.UpdateOperation ||
		!strings.HasSuffix(req.Path, "/config") {
		return "", nil
	}
	entry, backend := c.router.MatchingMountEntryAndBackend(ctx, req.Path)
	if entry == nil || entry.Class != mountClassAuth ||
		strings.TrimSuffix(strings.TrimPrefix(req.Path, authRoutePrefix), "config") != entry.Path {
		return "", nil
	}
	force := takeForce(req)
	fp, ok := backend.(logical.FactsProvider)
	if !ok {
		return "", nil
	}
	from, to := fp.AliasChange(req.Data)
	if from == "" || to == "" || from == to {
		return "", nil
	}
	mount := authRoutePrefix + entry.Path
	bound := c.identityStore.AliasesBoundTo(entry.Accessor)
	if bound == 0 {
		return "", nil
	}
	if !force {
		return "", logical.ErrConflictf(
			"after this write %s would derive native identities as %s (now %s) while %d are claimed on it: "+
				"they would no longer match the credentials they were claimed for; release or move them first, "+
				"or pass force=true", mount, to, from, bound)
	}
	c.logger.Warn("alias derivation changed while native identities are claimed on the mount (force)",
		logger.String("mount", mount),
		logger.String("mount_accessor", entry.Accessor),
		logger.String("from", from),
		logger.String("to", to),
		logger.Int("claimed", bound))
	return fmt.Sprintf("forced: %s now derives native identities as %s (was %s); the %d claimed on it no "+
		"longer match the credentials they were claimed for until they are claimed again", mount, to, from, bound), nil
}

// refuseAuthMountDisable guards disabling the auth mount at path (relative to
// auth/) while native identities are claimed on it: enabling it again makes a
// new accessor, so every claim on it would be left on a mount that no longer
// exists. Refused unless force is set, which is logged and returns a warning
// for the disable's response.
func (c *Core) refuseAuthMountDisable(ctx context.Context, path string, force bool) (warning string, err error) {
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}
	entry := c.router.MatchingMountEntry(ctx, authRoutePrefix+path)
	if entry == nil || entry.Class != mountClassAuth || entry.Path != path {
		return "", nil
	}
	bound := c.identityStore.AliasesBoundTo(entry.Accessor)
	if bound == 0 {
		return "", nil
	}
	if !force {
		return "", logical.ErrConflictf(
			"auth mount %s cannot be disabled while %d native identities are claimed on it: a mount enabled again "+
				"is a new mount, and the claims would be left on this one; release or move them first, or pass force=true",
			authRoutePrefix+path, bound)
	}
	c.logger.Warn("auth mount disabled while native identities are claimed on it (force)",
		logger.String("mount", authRoutePrefix+path),
		logger.String("mount_accessor", entry.Accessor),
		logger.Int("claimed", bound))
	return fmt.Sprintf("forced: %d native identities claimed on %s are orphaned (mount_accessor %s); "+
		"list them with LIST sys/identity/entity?orphaned=true", bound, authRoutePrefix+path, entry.Accessor), nil
}
