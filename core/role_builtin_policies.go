package core

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/stephnangue/warden/internal/namespace"
)

// builtinRolePolicies holds each built-in role's body compiled for a namespace,
// filled on first use. A request under a built-in attaches the body compiled
// for its token's namespace, beside the namespace's built-in policies.
//
// Reads are one atomic load and a map lookup, with no lock. A miss compiles
// that one body under mu and publishes a new map: copy on write, so a
// published map is never written again. A namespace's entries are dropped when
// the namespace is deleted; namespace UUIDs are never reused, so an entry
// outliving its namespace for a moment is harmless.
type builtinRolePolicies struct {
	mu sync.Mutex
	m  atomic.Pointer[map[builtinRolePolicyKey]*Policy]
}

type builtinRolePolicyKey struct {
	nsUUID string
	role   int // index in builtinRoles
}

// policy returns the body of the built-in at index role, compiled for ns. The
// policy is finalized and shared read only.
func (b *builtinRolePolicies) policy(ns *namespace.Namespace, role int) (*Policy, error) {
	key := builtinRolePolicyKey{nsUUID: ns.UUID, role: role}
	if m := b.m.Load(); m != nil {
		if p, ok := (*m)[key]; ok {
			return p, nil
		}
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	old := b.m.Load()
	if old != nil {
		if p, ok := (*old)[key]; ok {
			return p, nil
		}
	}
	p, err := compileBuiltinRole(ns, role)
	if err != nil {
		return nil, err
	}
	next := make(map[builtinRolePolicyKey]*Policy, mapLen(old)+1)
	if old != nil {
		for k, v := range *old {
			next[k] = v
		}
	}
	next[key] = p
	b.m.Store(&next)
	return p, nil
}

// drop forgets every body compiled for the namespace nsUUID.
func (b *builtinRolePolicies) drop(nsUUID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	old := b.m.Load()
	if old == nil {
		return
	}
	next := make(map[builtinRolePolicyKey]*Policy, len(*old))
	for k, v := range *old {
		if k.nsUUID != nsUUID {
			next[k] = v
		}
	}
	if len(next) != len(*old) {
		b.m.Store(&next)
	}
}

// compileBuiltinRole parses the body of the built-in at index role in ns. The
// policy takes the role's name, so audit's granting_policies names the role.
func compileBuiltinRole(ns *namespace.Namespace, role int) (*Policy, error) {
	r := builtinRoles[role]
	p, err := parseCBPPolicy(ns, r.body)
	if err != nil {
		return nil, fmt.Errorf("built-in role %q: %w", r.role.Name, err)
	}
	p.Name = r.role.Name
	p.finalize()
	return p, nil
}

func mapLen[K comparable, V any](m *map[K]V) int {
	if m == nil {
		return 0
	}
	return len(*m)
}
