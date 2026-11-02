// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// The built-in policies. Every namespace holds one of each, seeded when the
// namespace is created and, for namespaces that predate them, when the active
// node unseals. All are attached to every request that is not a root request,
// beside whatever policies the request's token or role carries, so a grant in
// any reaches every caller in the namespace. They are editable, emptying one
// is how an operator turns off what it grants, and they cannot be deleted.
//
// The seeded bodies name only the paths of their feature, each by its exact
// path or, for the sponsor paths, its exact shape (one "+" per entity name):
// neither is ever matched as a prefix, so attaching them everywhere changes no
// decision on any other path. Policy names stay unique across types, because
// a token's policy list is a flat list of names.
const (
	builtinCBPPolicy     = "default-cbp"
	builtinMCPPolicy     = "default-mcp"
	builtinSponsorPolicy = "default-sponsor"
)

// builtinCBPBody grants the discovery endpoints. read and delete on sys/mcp
// let a legacy client's GET and DELETE reach the MCP server's own 405 rather
// than a permission refusal.
const builtinCBPBody = `# Built-in policy, attached to every request in this namespace that is not
# a root request. Empty it, or deny these paths, to turn discovery off.
path "sys/mcp" {
  capabilities = ["create", "read", "delete"]
}

path "sys/introspect/roles" {
  capabilities = ["read"]
}
`

// builtinMCPBody is the tool contract of Warden's own discovery server.
// initialize, ping, server/discover and notifications/* need no entry: the
// lifecycle methods are exempt from every MCP contract.
const builtinMCPBody = `# Built-in policy, attached to every request in this namespace that is not
# a root request. It governs Warden's own discovery server only.
path "sys/mcp" {
  methods {
    allowed = [
      "tools/list",
      "tools/call",
      "resources/list",
      "resources/read",
      "resources/templates/list",
      "skills/list",
      "skills/get",
      "subscriptions/listen",
      "logging/setLevel",
    ]
  }

  tools {
    allowed = ["list_roles", "read_skill"]
  }

  resources {
    allowed = ["skill://*"]
  }
}
`

// builtinSponsorBody lets a sponsor's request reach the sponsor handlers,
// which decide who sponsors what: the request must be a human's ticket, and
// the human a member of the entity's sponsor group. It is its own built-in so
// that emptying it turns sponsors off without touching discovery.
const builtinSponsorBody = `# Built-in policy, attached to every request in this namespace that is not
# a root request. Empty it to turn sponsors off here. The handlers decide who
# sponsors what; these entries only let a sponsor's request reach them.
path "sys/identity/sponsor/+" {
  capabilities = ["read"]
}

path "sys/identity/sponsor/+/suspend" {
  capabilities = ["create", "update"]
}

path "sys/identity/sponsor/+/handover" {
  capabilities = ["create", "update"]
}

path "sys/identity/sponsor/+/accept" {
  capabilities = ["create", "update"]
}
`

// builtinPolicy is one built-in: its name, its type and its seeded body.
type builtinPolicy struct {
	name       string
	policyType PolicyType
	body       string
}

// builtinPolicies lists the built-ins in the order they are attached.
var builtinPolicies = []builtinPolicy{
	{name: builtinCBPPolicy, policyType: PolicyTypeCBP, body: builtinCBPBody},
	{name: builtinMCPPolicy, policyType: PolicyTypeMCP, body: builtinMCPBody},
	{name: builtinSponsorPolicy, policyType: PolicyTypeCBP, body: builtinSponsorBody},
}

// builtinDiscoveryPaths are the paths the built-ins are meant to govern.
var builtinDiscoveryPaths = []string{"sys/mcp", "sys/introspect/roles"}

// builtinSponsorPaths are the shapes of the sponsor paths the built-ins
// govern: an entity name, then at most a verb. They are the only stanzas
// with a segment wildcard a built-in may hold without a warning.
var builtinSponsorPaths = []string{
	"sys/identity/sponsor/+",
	"sys/identity/sponsor/+/suspend",
	"sys/identity/sponsor/+/handover",
	"sys/identity/sponsor/+/accept",
}

// isReservedPolicyName reports whether name, already canonical, is reserved
// for built-in policies: "default" and every "default-" name. Names reserved
// this way can be written only as the built-in of the matching type.
func isReservedPolicyName(name string) bool {
	return name == "default" || strings.HasPrefix(name, "default-")
}

// isBuiltinPolicy reports whether (name, policyType) is a built-in.
func isBuiltinPolicy(name string, policyType PolicyType) bool {
	for _, b := range builtinPolicies {
		if b.name == name && b.policyType == policyType {
			return true
		}
	}
	return false
}

// errReservedPolicyName refuses a write to a reserved name.
var errReservedPolicyName = logical.ErrBadRequest(`policy names "default" and "default-*" are reserved for built-in policies`)

// seedDefaultPolicies writes the built-ins into the namespace in ctx when they
// are absent, and warns about any other policy left in the reserved space. It
// never overwrites a policy: an operator's edit, an emptied body included,
// survives every unseal.
//
// A built-in name already held by a policy of the other type (written before
// the names were reserved) is not seeded: the conflict is logged so the
// operator can rename that policy, and until then the built-in is missing.
func (ps *PolicyStore) seedDefaultPolicies(ctx context.Context) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}
	for _, b := range builtinPolicies {
		if err := ps.seedBuiltinPolicy(ctx, ns, b); err != nil {
			return fmt.Errorf("seed policy %q: %w", b.name, err)
		}
	}
	ps.warnLegacyReservedPolicies(ctx, ns)
	return nil
}

func (ps *PolicyStore) seedBuiltinPolicy(ctx context.Context, ns *namespace.Namespace, b builtinPolicy) error {
	ps.modifyLock.Lock()
	defer ps.modifyLock.Unlock()

	view := ps.getBarrierView(ns, b.policyType)
	if view == nil {
		return fmt.Errorf("no storage view for %s policies", b.policyType)
	}
	existing, err := view.Get(ctx, b.name)
	if err != nil {
		return err
	}
	if existing != nil {
		return nil
	}

	otherType := PolicyTypeMCP
	if b.policyType == PolicyTypeMCP {
		otherType = PolicyTypeCBP
	}
	if otherView := ps.getBarrierView(ns, otherType); otherView != nil {
		conflict, err := otherView.Get(ctx, b.name)
		if err != nil {
			return err
		}
		if conflict != nil {
			ps.logger.Error("built-in policy not seeded: its name is held by a policy of the other type; rename that policy",
				logger.String("namespace", ns.Path),
				logger.String("policy", b.name),
				logger.String("held_by_type", otherType.String()))
			return nil
		}
	}

	p, err := parsePolicyForType(ns, b.body, b.policyType)
	if err != nil {
		return fmt.Errorf("parse built-in body: %w", err)
	}
	p.Name, p.Type = b.name, b.policyType
	return ps.setPolicyLocked(ctx, p, nil)
}

// warnLegacyReservedPolicies logs, once per namespace, the policies stored
// under a reserved name that are not built-ins: written before the names were
// reserved, they can still be read and deleted but no longer updated, and no
// request is given them.
func (ps *PolicyStore) warnLegacyReservedPolicies(ctx context.Context, ns *namespace.Namespace) {
	var legacy []string
	for _, policyType := range []PolicyType{PolicyTypeCBP, PolicyTypeMCP} {
		names, err := ps.ListPolicies(ctx, policyType, false)
		if err != nil {
			ps.logger.Warn("could not list policies to check reserved names",
				logger.String("namespace", ns.Path), logger.Err(err))
			continue
		}
		for _, name := range names {
			if isReservedPolicyName(name) && !isBuiltinPolicy(name, policyType) {
				legacy = append(legacy, policyType.String()+"/"+name)
			}
		}
	}
	if len(legacy) == 0 {
		return
	}
	slices.Sort(legacy)
	ps.logger.Warn(`policies use names reserved for built-in policies ("default", "default-*"): `+
		"they can be read and deleted but not updated, and no request is given them; rename them",
		logger.String("namespace", ns.Path),
		logger.String("policies", strings.Join(legacy, ", ")))
}

// appendDefaultPolicies appends the built-ins of the namespace in ctx to dst,
// to attach to a request, and returns the extended slice.
//
// It runs on every request that is not a root request, so the common case, a
// built-in in the policy cache, allocates nothing: the cache is probed first,
// directly. Only past a cache miss is the missing set consulted (its keys are
// boxed, which allocates) and the store asked. A built-in that is missing is
// skipped, and remembered as missing until a policy of that name is next
// written: absence is not cached by GetPolicy, so without this every request
// would take the store's exclusive lock to look for it again.
func (ps *PolicyStore) appendDefaultPolicies(ctx context.Context, dst []*Policy) ([]*Policy, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return dst, err
	}
	for _, b := range builtinPolicies {
		key := ps.cacheKey(ns, b.name, b.policyType)
		if ps.tokenPoliciesLRU != nil {
			if p, ok := ps.tokenPoliciesLRU.Get(key); ok && (p.Expiration.IsZero() || time.Now().Before(p.Expiration)) {
				dst = append(dst, p)
				continue
			}
		}
		gen := ps.builtinGen.Load()
		if seen, ok := ps.missingBuiltins.Load(key); ok && seen.(uint64) == gen {
			continue
		}
		p, err := ps.GetPolicy(ctx, b.name, b.policyType)
		if err != nil {
			return dst, err
		}
		if p == nil {
			if _, loaded := ps.missingBuiltins.Swap(key, gen); !loaded {
				ps.logger.Warn("built-in policy missing; requests in this namespace get none of its grants",
					logger.String("namespace", ns.Path),
					logger.String("policy", b.name))
			}
			continue
		}
		dst = append(dst, p)
	}
	return dst, nil
}

// builtinPolicyWarnings returns the write-time warnings for p, a policy about
// to be stored. A built-in is attached to every request, so a stanza outside
// the discovery paths widens every caller in the namespace. Any other policy
// stanza on a discovery path that carries a condition, or an MCP contract,
// does not narrow what the built-ins grant there: policies merge, a merged-in
// stanza without a condition makes the path unconditional, and MCP rule-sets
// are alternatives. Only an exact-path deny narrows discovery for a role.
func builtinPolicyWarnings(p *Policy) []string {
	var warnings []string
	if isBuiltinPolicy(p.Name, p.Type) {
		for _, pr := range p.Paths {
			if !isDiscoveryStanza(p, pr) {
				warnings = append(warnings, fmt.Sprintf(
					"policy %q is attached to every request in this namespace: path %q now applies to every caller",
					p.Name, policyPathDisplay(p, pr)))
			}
		}
		return warnings
	}
	for _, pr := range p.Paths {
		if !isDiscoveryStanza(p, pr) {
			continue
		}
		conditional := pr.Permissions != nil && len(pr.Permissions.Conditions) > 0
		if p.Type == PolicyTypeMCP || conditional {
			warnings = append(warnings, fmt.Sprintf(
				"path %q is also granted by the built-in policies, which merge with this one: "+
					"a condition or an MCP contract here does not narrow discovery; only a deny does",
				policyPathDisplay(p, pr)))
		}
	}
	return warnings
}

// isDiscoveryStanza reports whether pr names exactly one of the paths the
// built-ins govern: a discovery path, or a sponsor path's exact shape. A
// prefix never does, nor any other segment wildcard. Parsed paths carry the
// policy's namespace path in front.
func isDiscoveryStanza(p *Policy, pr *PathRules) bool {
	if pr.IsPrefix {
		return false
	}
	if pr.HasSegmentWildcards {
		return slices.Contains(builtinSponsorPaths, policyRelativePath(p, pr))
	}
	return slices.Contains(builtinDiscoveryPaths, policyRelativePath(p, pr))
}

// policyRelativePath returns pr's path without the policy's namespace path.
func policyRelativePath(p *Policy, pr *PathRules) string {
	if p.namespace == nil {
		return pr.Path
	}
	return strings.TrimPrefix(pr.Path, p.namespace.Path)
}

// policyPathDisplay renders a parsed path stanza as it was written.
func policyPathDisplay(p *Policy, pr *PathRules) string {
	path := policyRelativePath(p, pr)
	if pr.IsPrefix {
		return path + "*"
	}
	return path
}
