package core

import (
	"context"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logger"
)

const (
	// policySubPath is the sub-path used for the policy store view. This is
	// nested under the system view.
	policySubPath = "policy/"

	// cbpSubPath is the sub-path used for the policy of type CBP. This is
	// nested under policySubPath.
	cbpSubPath = "cbp/"

	// policyCacheSize is the number of policies that are kept cached
	policyCacheSize = 1024

	// compiledCBPCacheSize is the number of compiled CBP objects kept cached.
	// Unlike the policy cache, which is keyed per individual policy (bounded by
	// how many policies are authored), this cache is keyed per policy SET — the
	// sorted tuple of all policies a token carries. Distinct policy-set ×
	// version combinations are combinatorial and typically outnumber distinct
	// policies, so it is sized larger. Correctness never depends on the size: a
	// miss simply recompiles, so this is purely a hit-rate tuning knob.
	compiledCBPCacheSize = 4096
)

var (
	immutablePolicies = []string{
		"root",
	}
	nonAssignablePolicies = []string{}
)

// PolicyStore is used to provide durable storage of policy, and to
// manage CBPs associated with them.
type PolicyStore struct {
	core *Core

	tokenPoliciesLRU *lru.TwoQueueCache[string, *Policy]

	// compiledCBPLRU caches compiled CBP objects keyed by the policy set they
	// were built from (see compiledCBPCacheKey). A policy edit bumps its
	// DataVersion, which changes the key, so stale entries are never served and
	// age out via the LRU. Entries also carry a time-validity bound to honour
	// per-path expirations (see compiledCBPEntry).
	compiledCBPLRU *lru.TwoQueueCache[string, *compiledCBPEntry]

	modifyLock *sync.RWMutex

	logger *logger.GatedLogger
}

// compiledCBPEntry is a cached compiled CBP together with the instant after
// which it must be recomputed. validUntil is the earliest future per-path
// expiration across the policy set; a zero value means no path expires, so the
// entry never times out (it can still be evicted by the LRU or superseded by a
// version bump).
type compiledCBPEntry struct {
	cbp        *CBP
	validUntil time.Time
}

// PolicyEntry is used to store a policy by name
type PolicyEntry struct {
	Version     int
	DataVersion int
	CASRequired bool
	Raw         string
	Templated   bool
	Type        PolicyType
	Expiration  time.Time
	Modified    time.Time
}

// NewPolicyStore creates a new PolicyStore
func NewPolicyStore(ctx context.Context, core *Core, logger *logger.GatedLogger) (*PolicyStore, error) {
	ps := &PolicyStore{
		modifyLock: new(sync.RWMutex),
		logger:     logger,
		core:       core,
	}

	cache, _ := lru.New2Q[string, *Policy](policyCacheSize)
	ps.tokenPoliciesLRU = cache

	compiledCache, _ := lru.New2Q[string, *compiledCBPEntry](compiledCBPCacheSize)
	ps.compiledCBPLRU = compiledCache

	return ps, nil
}

// setupPolicyStore is used to initialize the policy store
// when the Warden is being unsealed.
func (c *Core) setupPolicyStore(ctx context.Context) error {
	// Create the policy store
	var err error
	psLogger := c.logger.WithSystem("policy")
	c.policyStore, err = NewPolicyStore(ctx, c, psLogger)
	if err != nil {
		return err
	}

	// Ensure that the default policies exists, and if not, create them
	if err := c.policyStore.loadDefaultPolicies(ctx); err != nil {
		return err
	}

	return nil
}

// teardownPolicyStore is used to reverse setupPolicyStore
// when the Warden is being sealed.
func (c *Core) teardownPolicyStore() error {
	c.policyStore = nil
	return nil
}

func (ps *PolicyStore) invalidateNamespace(ctx context.Context, uuid string) {
	ps.modifyLock.Lock()
	defer ps.modifyLock.Unlock()

	for _, key := range ps.tokenPoliciesLRU.Keys() {
		if strings.HasPrefix(key, uuid) {
			ps.tokenPoliciesLRU.Remove(key)
		}
	}
}

func (ps *PolicyStore) invalidate(ctx context.Context, name string, policyType PolicyType) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}

	// This may come with a prefixed "/" due to joining the file path
	saneName := strings.TrimPrefix(name, "/")
	index := ps.cacheKey(ns, saneName)

	ps.modifyLock.Lock()
	defer ps.modifyLock.Unlock()

	// We don't lock before removing from the LRU here because the worst that
	// can happen is we load again if something since added it
	switch policyType {
	case PolicyTypeCBP:
		if ps.tokenPoliciesLRU != nil {
			ps.tokenPoliciesLRU.Remove(index)
		}

	default:
		return fmt.Errorf("unknown policy type: %w", err)
	}

	return nil
}

// SetPolicy is used to create or update the given policy
func (ps *PolicyStore) SetPolicy(ctx context.Context, p *Policy, casVersion *int) error {
	if p == nil {
		return errors.New("nil policy passed in for storage")
	}
	if p.Name == "" {
		return errors.New("policy name missing")
	}
	// Policies are normalized to lower-case
	p.Name = ps.sanitizeName(p.Name)
	if slices.Contains(immutablePolicies, p.Name) {
		return fmt.Errorf("cannot update %q policy", p.Name)
	}

	return ps.setPolicyInternal(ctx, p, casVersion)
}

func (ps *PolicyStore) setPolicyInternal(ctx context.Context, p *Policy, casVersion *int) error {
	ps.modifyLock.Lock()
	defer ps.modifyLock.Unlock()

	// Get the appropriate view based on policy type and namespace
	view := ps.getBarrierView(p.namespace, p.Type)

	p.Modified = time.Now()

	existingEntry, err := view.Get(ctx, p.Name)
	if err != nil {
		return fmt.Errorf("unable to get existing policy for check-and-set: %w", err)
	}

	var existing PolicyEntry
	if existingEntry != nil {
		if err := existingEntry.DecodeJSON(&existing); err != nil {
			return fmt.Errorf("failed to decode existing policy: %w", err)
		}
	}

	casRequired := existing.CASRequired || p.CASRequired
	if casVersion == nil && casRequired {
		return fmt.Errorf("check-and-set parameter required for this call")
	}
	if casVersion != nil {
		if *casVersion == -1 && existingEntry != nil {
			return fmt.Errorf("check-and-set parameter set to -1 on existing entry")
		}

		if *casVersion != -1 && *casVersion != existing.DataVersion {
			return fmt.Errorf("check-and-set parameter did not match the current version")
		}
	}

	// Create the entry
	p.DataVersion = existing.DataVersion + 1
	entry, err := sdklogical.StorageEntryJSON(p.Name, &PolicyEntry{
		Version:     2,
		DataVersion: p.DataVersion,
		CASRequired: p.CASRequired,
		Raw:         p.Raw,
		Type:        p.Type,
		Templated:   p.Templated,
		Expiration:  p.Expiration,
		Modified:    p.Modified,
	})
	if err != nil {
		return fmt.Errorf("failed to create entry: %w", err)
	}

	// Construct the cache key
	index := ps.cacheKey(p.namespace, p.Name)

	switch p.Type {
	case PolicyTypeCBP:
		if err := view.Put(ctx, entry); err != nil {
			return fmt.Errorf("failed to persist policy: %w", err)
		}

		if ps.tokenPoliciesLRU != nil {
			ps.tokenPoliciesLRU.Add(index, p)
		}
	default:
		return errors.New("unknown policy type, cannot set")
	}

	return nil
}

// getCBPView returns the CBP view for the given namespace
func (ps *PolicyStore) getCBPView(ns *namespace.Namespace) BarrierView {
	if ns.ID == namespace.RootNamespaceID {
		return ps.core.systemBarrierView.SubView(policySubPath + cbpSubPath)
	}

	return ps.core.namespaceMountEntryView(ns, systemBarrierPrefix+policySubPath+cbpSubPath)
}

// getBarrierView returns the appropriate barrier view for the given namespace and policy type.
// Currently, this only supports CBP policies, so it delegates to getCBPView.
func (ps *PolicyStore) getBarrierView(ns *namespace.Namespace, _ PolicyType) BarrierView {
	return ps.getCBPView(ns)
}

// GetPolicy is used to fetch the named policy
func (ps *PolicyStore) GetPolicy(ctx context.Context, name string, policyType PolicyType) (*Policy, error) {
	return ps.switchedGetPolicy(ctx, name, policyType, true)
}

func (ps *PolicyStore) switchedGetPolicy(ctx context.Context, name string, policyType PolicyType, grabLock bool) (*Policy, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	// Policies are normalized to lower-case
	name = ps.sanitizeName(name)
	index := ps.cacheKey(ns, name)

	var cache *lru.TwoQueueCache[string, *Policy]
	var view BarrierView

	switch policyType {
	case PolicyTypeCBP:
		cache = ps.tokenPoliciesLRU
		view = ps.getCBPView(ns)
		policyType = PolicyTypeCBP
	}

	if cache != nil {
		// Check for cached policy.
		if raw, ok := cache.Get(index); ok {
			// Check for expiration of cached policy.
			if !raw.Expiration.IsZero() && time.Now().After(raw.Expiration) {
				// Only remove the entry from cache; we have not locked the
				// store so a change might have modified it but hasn't yet
				// invalidated the cache entry.
				//
				// We remove it from cache and fall through to fetching the
				// actual policy here.
				cache.Remove(index)
			} else {
				return raw, nil
			}
		}
	}

	// Special case the root policy
	if policyType == PolicyTypeCBP && name == "root" && ns.ID == namespace.RootNamespaceID {
		p := &Policy{
			Name:      "root",
			namespace: namespace.RootNamespace,
			Type:      PolicyTypeCBP,
		}
		if cache != nil {
			cache.Add(index, p)
		}
		return p, nil
	}

	if grabLock {
		ps.modifyLock.Lock()
		defer ps.modifyLock.Unlock()
	}

	// See if anything has added it since we got the lock. At this point,
	// any subsequent writes would be committed, so if this policy were then
	// read ahead of us getting the write lock, it would be up-to-date (as
	// write would've removed the policy). However, all this could've occurred
	// after our earlier cache read above.
	if cache != nil {
		if raw, ok := cache.Get(index); ok {
			// Check for expiration of cached policy.
			if !raw.Expiration.IsZero() && time.Now().After(raw.Expiration) {
				// This is an odd edge case. We have the entry in cache and we
				// know nobody else has yet modified it in storage, otherwise
				// we wouldn't have held the modifyLock. Remove it both from
				// cache and from storage.
				if err := view.Delete(ctx, name); err != nil {
					return nil, fmt.Errorf("failed to remove expired policy: %w", err)
				}

				cache.Remove(index)
				return nil, nil
			}

			return raw, nil
		}
	}

	// Nil-check on the view before proceeding to retrieve from storage
	if view == nil {
		return nil, fmt.Errorf("unable to get the barrier subview for policy type %q", policyType)
	}

	out, err := view.Get(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy: %w", err)
	}

	if out == nil {
		return nil, nil
	}

	policyEntry := new(PolicyEntry)
	policy := new(Policy)
	err = out.DecodeJSON(policyEntry)
	if err != nil {
		return nil, fmt.Errorf("failed to parse policy: %w", err)
	}

	// Handle expiration, removing the entry if it is expired.
	if !policyEntry.Expiration.IsZero() && time.Now().After(policyEntry.Expiration) {
		if err := view.Delete(ctx, name); err != nil {
			return nil, fmt.Errorf("failed to remove expired policy: %w", err)
		}

		return nil, nil
	}

	// Set these up here so that they're available for loading into
	// Sentinel
	policy.Name = name
	policy.DataVersion = policyEntry.DataVersion
	policy.CASRequired = policyEntry.CASRequired
	policy.Raw = policyEntry.Raw
	policy.Type = policyEntry.Type
	policy.Templated = policyEntry.Templated
	policy.Expiration = policyEntry.Expiration
	policy.Modified = policyEntry.Modified
	policy.namespace = ns
	switch policyEntry.Type {
	case PolicyTypeCBP:
		// Parse normally
		p, err := ParseCBPPolicy(ns, policyEntry.Raw)
		if err != nil {
			return nil, fmt.Errorf("failed to parse policy: %w", err)
		}
		policy.Paths = p.Paths

		// Reset this in case they set the name in the policy itself
		policy.Name = name
	default:
		return nil, fmt.Errorf("unknown policy type %q", policyEntry.Type.String())
	}

	if cache != nil {
		// Update the LRU cache
		cache.Add(index, policy)
	}

	return policy, nil
}

// ListPolicies is used to list the available policies
func (ps *PolicyStore) ListPolicies(ctx context.Context, policyType PolicyType, omitNonAssignable bool) ([]string, error) {
	return ps.ListPoliciesWithPrefix(ctx, policyType, "", omitNonAssignable)
}

// ListPoliciesWithPrefix is used to list policies with the given prefix in the specified namespace
// omitNonAssignable dictates whether result list
// should also contain the nonAssignable policies
func (ps *PolicyStore) ListPoliciesWithPrefix(ctx context.Context, policyType PolicyType, prefix string, omitNonAssignable bool) ([]string, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	if ns == nil {
		return nil, namespace.ErrNoNamespace
	}

	// Get the appropriate view based on policy type and namespace
	view := ps.getBarrierView(ns, policyType)

	// Scan the view, since the policy names are the same as the
	// key names.
	var keys []string
	switch policyType {
	case PolicyTypeCBP:
		keys, err = sdklogical.CollectKeysWithPrefix(ctx, view, prefix)
	default:
		return nil, fmt.Errorf("unknown policy type %q", policyType)
	}

	if omitNonAssignable {
		keys = slices.DeleteFunc(keys, func(policyName string) bool {
			return slices.Contains(nonAssignablePolicies, policyName)
		})
	}

	return keys, err
}

// DeletePolicy is used to delete the named policy
func (ps *PolicyStore) DeletePolicy(ctx context.Context, name string, policyType PolicyType) error {
	return ps.switchedDeletePolicy(ctx, name, policyType, true, false)
}

// deletePolicyForce is used to delete the named policy and force it even if
// default or a singleton. It's used for invalidations or namespace deletion
// where we internally need to actually remove a policy that the user normally
// isn't allowed to remove.
func (ps *PolicyStore) deletePolicyForce(ctx context.Context, name string, policyType PolicyType) error {
	return ps.switchedDeletePolicy(ctx, name, policyType, true, true)
}

func (ps *PolicyStore) switchedDeletePolicy(ctx context.Context, name string, policyType PolicyType, physicalDeletion, force bool) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}
	// If not set, the call comes from invalidation, where we'll already have
	// grabbed the lock
	if physicalDeletion {
		ps.modifyLock.Lock()
		defer ps.modifyLock.Unlock()
	}

	// Policies are normalized to lower-case
	name = ps.sanitizeName(name)
	index := ps.cacheKey(ns, name)

	view := ps.getBarrierView(ns, policyType)

	switch policyType {
	case PolicyTypeCBP:
		if !force {
			if slices.Contains(immutablePolicies, name) {
				return fmt.Errorf("cannot delete %q policy", name)
			}
			if name == "default" {
				return errors.New("cannot delete default policy")
			}
		}

		if physicalDeletion {
			err := view.Delete(ctx, name)
			if err != nil {
				return fmt.Errorf("failed to delete policy: %w", err)
			}
		}

		if ps.tokenPoliciesLRU != nil {
			// Clear the cache
			ps.tokenPoliciesLRU.Remove(index)
		}
	}

	return nil
}

// CBP is used to return an CBP which is built using the
// named policies and pre-fetched policies if given.
func (ps *PolicyStore) CBP(ctx context.Context, policyNames map[string][]string, additionalPolicies ...*Policy) (*CBP, error) {
	var allPolicies []*Policy

	// Fetch the named policies
	for nsID, nsPolicyNames := range policyNames {
		policyNS, err := ps.core.NamespaceByID(ctx, nsID)
		if err != nil {
			return nil, err
		}
		if policyNS == nil {
			return nil, namespace.ErrNoNamespace
		}
		policyCtx := namespace.ContextWithNamespace(ctx, policyNS)
		for _, nsPolicyName := range nsPolicyNames {
			p, err := ps.GetPolicy(policyCtx, nsPolicyName, PolicyTypeCBP)
			if err != nil {
				return nil, fmt.Errorf("failed to get policy: %w", err)
			}
			if p != nil {
				allPolicies = append(allPolicies, p)
			}
		}
	}

	// Append any pre-fetched policies that were given
	allPolicies = append(allPolicies, additionalPolicies...)

	for i, policy := range allPolicies {
		// Reuse the parse already performed and cached by GetPolicy. Re-parse
		// only when a prefetched policy arrived without parsed paths. CBP
		// policies carry no per-request templating, so a cached parse is always
		// reusable and never identity-dependent.
		if policy.Type == PolicyTypeCBP && policy.Paths == nil {
			p, err := parseCBPPolicy(policy.namespace, policy.Raw)
			if err != nil {
				return nil, fmt.Errorf("error parsing policy %q: %w", policy.Name, err)
			}
			p.Name = policy.Name
			allPolicies[i] = p
		}
	}

	// Serve a previously compiled CBP when the exact same policy set (by name
	// and version) was already compiled. Prefetched policies are not keyed from
	// storage and may be ephemeral, so the cache is bypassed when any are given.
	cacheable := len(additionalPolicies) == 0 && ps.compiledCBPLRU != nil
	var cacheKey string
	if cacheable {
		cacheKey = compiledCBPCacheKey(allPolicies)
		if entry, ok := ps.compiledCBPLRU.Get(cacheKey); ok {
			if entry.validUntil.IsZero() || time.Now().Before(entry.validUntil) {
				return entry.cbp, nil
			}
			// A per-path expiration has elapsed; drop and recompile.
			ps.compiledCBPLRU.Remove(cacheKey)
		}
	}

	// Construct the CBP
	cbp, err := NewCBP(ctx, allPolicies)
	if err != nil {
		return nil, fmt.Errorf("failed to construct CBP: %w", err)
	}

	if cacheable {
		ps.compiledCBPLRU.Add(cacheKey, &compiledCBPEntry{
			cbp:        cbp,
			validUntil: earliestPathExpiration(allPolicies),
		})
	}

	return cbp, nil
}

// compiledCBPCacheKey builds a stable, order-independent key identifying a
// policy set. Each policy contributes its namespace, name, data version, and
// policy-level expiration; a version bump therefore yields a new key so edits
// are never served from a stale compiled CBP. Per-path expirations are not part
// of the key (they are time-driven, not version-driven) and are handled via the
// entry's validUntil bound instead.
func compiledCBPCacheKey(policies []*Policy) string {
	tuples := make([]string, 0, len(policies))
	for _, p := range policies {
		if p == nil {
			continue
		}
		nsUUID := ""
		if p.namespace != nil {
			nsUUID = p.namespace.UUID
		}
		tuples = append(tuples, fmt.Sprintf("%s\x1f%s\x1f%d\x1f%d",
			nsUUID, p.Name, p.DataVersion, p.Expiration.Unix()))
	}
	slices.Sort(tuples)
	return strings.Join(tuples, "\x1e")
}

// earliestPathExpiration returns the soonest future per-path expiration across
// the policy set, which bounds how long a compiled CBP stays valid (NewCBP
// drops already-expired paths at compile time). Already-elapsed expirations are
// ignored. A zero return means no path expires, so the compiled CBP has no time
// bound.
func earliestPathExpiration(policies []*Policy) time.Time {
	now := time.Now()
	var earliest time.Time
	for _, p := range policies {
		if p == nil {
			continue
		}
		for _, pc := range p.Paths {
			if pc.Expiration.IsZero() || !pc.Expiration.After(now) {
				continue
			}
			if earliest.IsZero() || pc.Expiration.Before(earliest) {
				earliest = pc.Expiration
			}
		}
	}
	return earliest
}

// loadCBPPolicy is used to load default CBP policies in a specific
// namespace.
func (ps *PolicyStore) loadCBPPolicy(ctx context.Context, policyName, policyText string) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}

	// Check if the policy already exists
	policy, err := ps.GetPolicy(ctx, policyName, PolicyTypeCBP)
	if err != nil {
		return fmt.Errorf("error fetching %s policy from store: %w", policyName, err)
	}
	if policy != nil {
		if !slices.Contains(immutablePolicies, policyName) || policyText == policy.Raw {
			return nil
		}
	}

	policy, err = ParseCBPPolicy(ns, policyText)
	if err != nil {
		return fmt.Errorf("error parsing %s policy: %w", policyName, err)
	}

	if policy == nil {
		return fmt.Errorf("parsing %q policy resulted in nil policy", policyName)
	}

	cas := &policy.DataVersion
	policy.Name = policyName
	policy.Type = PolicyTypeCBP
	return ps.setPolicyInternal(ctx, policy, cas)
}

func (ps *PolicyStore) sanitizeName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

func (ps *PolicyStore) cacheKey(ns *namespace.Namespace, name string) string {
	return path.Join(ns.UUID, name)
}

// loadDefaultPolicies loads default policies for the namespace in the provided context
func (ps *PolicyStore) loadDefaultPolicies(ctx context.Context) error {
	// There is no default policy for now

	return nil
}
