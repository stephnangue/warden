package core

import (
	"fmt"

	"github.com/stephnangue/warden/logical"
)

// identityVerdict judges an agent admitted as adm, whose membership m
// resolved its entity of record (m.Entity, nil when unclaimed), in a namespace
// configured by cfg, before any role is considered. It returns the
// logical.RoleDenied* reason unknown_aliases=deny refuses the caller for ("" when
// it admits it), and whether the caller is refused for it in the mode in force:
//
//   - A claimed caller whose entity is suspended or retired is refused in every
//     mode, whatever its mount: the kill switch.
//   - Unless the caller's mount is exempt, a caller that presents no native
//     identity, one no entity claims, and one whose entity is not governed get
//     their reason in every mode, and are refused for it under deny only.
//     Under observe the reason is what deny would refuse them for: the dry run
//     audit records.
//
// A human admission is never judged: humans are never claimed, and their roles
// come from their groups alone. It does not allocate.
func identityVerdict(cfg *identityConfig, adm *logical.Admission, m *logical.Membership) (reason string, refused bool) {
	if adm.Kind == logical.EntityKindHuman || (m.Naming != nil && m.Naming.Kind == logical.EntityKindHuman) {
		return "", false
	}
	if e := m.Entity; e != nil {
		switch e.State {
		case logical.EntityStateSuspended:
			return logical.RoleDeniedEntitySuspended, true
		case logical.EntityStateRetired:
			return logical.RoleDeniedEntityRetired, true
		}
	}
	if cfg.exempt(adm.MountAccessor) {
		return "", false
	}
	switch {
	case adm.AliasName == "":
		reason = logical.RoleDeniedIdentityNone
	case m.Entity == nil:
		reason = logical.RoleDeniedIdentityUnclaimed
	case m.Entity.GovernedBy() == "":
		reason = logical.RoleDeniedEntityNotGoverned
	default:
		return "", false
	}
	return reason, cfg.mode() == unknownAliasesDeny
}

// identityRefusalMessage words an identity verdict's refusal for the caller,
// naming the native identity it presented, as (mount, alias), and the entity
// that claims it. The caller is the agent itself, so it learns only about
// itself. Built on the refused path only. ok is false for a reason that is not
// an identity verdict's.
func identityRefusalMessage(reason string, te *logical.TokenEntry) (msg string, ok bool) {
	var mount, alias string
	if te != nil && te.Admission != nil {
		mount, alias = te.Admission.MountPath, te.Admission.AliasName
	}
	var entity string
	if te != nil && te.Entity != nil {
		entity = te.Entity.Name
	}
	identity := fmt.Sprintf("native identity (%s, %s)", mount, alias)
	switch reason {
	case logical.RoleDeniedIdentityNone:
		return fmt.Sprintf("the credential presents no native identity through %s; unknown_aliases=deny "+
			"(check the alias_name_source of %s)", mount, mount), true
	case logical.RoleDeniedIdentityUnclaimed:
		return identity + " is unclaimed; unknown_aliases=deny", true
	case logical.RoleDeniedEntitySuspended:
		return fmt.Sprintf("%s belongs to entity %q, which is suspended", identity, entity), true
	case logical.RoleDeniedEntityRetired:
		return fmt.Sprintf("%s belongs to entity %q, which is retired", identity, entity), true
	case logical.RoleDeniedEntityNotGoverned:
		// What the entity lacks is an admin's business (entity read says it);
		// the agent learns only that it is not governed.
		return fmt.Sprintf("%s belongs to entity %q, which is not governed; unknown_aliases=deny", identity, entity), true
	}
	return "", false
}
