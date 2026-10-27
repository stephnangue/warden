package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/hashicorp/go-uuid"
	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/helper/selector"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

var (
	ErrGroupNotFound        = errors.New("group not found")
	ErrGroupAlreadyExists   = errors.New("group already exists")
	ErrTooManyVirtualGroups = errors.New("too many virtual groups in the namespace")
	ErrTooManySelectors     = errors.New("too many selectors in the namespace")

	// ErrGroupChanged is returned by UpdateGroup and DeleteGroup when the
	// caller passed an expected hash and the stored group no longer has it.
	ErrGroupChanged = errors.New("group changed concurrently")
)

// GroupTypeMismatchError is returned when a request names a group type other
// than the stored one. Every group write carries the type, so a policy
// condition on it can tell who may write which type of group.
type GroupTypeMismatchError struct {
	Name   string
	Stored logical.GroupType
}

func (e *GroupTypeMismatchError) Error() string {
	return fmt.Sprintf("type mismatch: group %q is %s", e.Name, e.Stored)
}

// Storage layout, under the barrier view at identityStorePath:
//
//	{namespace-uuid}/group/{id} -> JSON-encoded StoredGroup
//
// A group is stored under its ID, not its name, so that what references a
// group (a static group's members, in time) does so by a key that never
// changes.
const (
	groupKeySegment    = "group/"
	storedGroupVersion = 1
)

// StoredGroup is the versioned storage format for a group. Version lets a later
// format be recognised on read; Hash is the group's content hash at the write.
type StoredGroup struct {
	Version int            `json:"version"`
	Group   *logical.Group `json:"group"`
	Hash    string         `json:"hash"`
}

func groupListPrefix(nsUUID string) string { return nsUUID + "/" + groupKeySegment }

func groupStorageKey(nsUUID, id string) string { return groupListPrefix(nsUUID) + id }

// GroupsListingRole returns the names of the groups of namespace nsID that
// list role, sorted.
func (s *IdentityStore) GroupsListingRole(nsID, role string) []string {
	return s.namespaceIndex(nsID).listing(role)
}

// publishGroupsLocked makes byName the namespace's groups under the next generation,
// keeping its entities as published. Caller holds mu and hands over byName.
func (s *IdentityStore) publishGroupsLocked(nsID string, byName map[string]*groupEntry) {
	snap := s.snapshot.Load()
	ents := snap.namespace(nsID).entities
	s.snapshot.Store(snap.withNamespace(nsID, buildNSIndex(byName, ents, s.gen.Add(1))))
}

// GetGroup returns a copy of the group name in the namespace in ctx, and the
// hash a conditional write passes back.
func (s *IdentityStore) GetGroup(ctx context.Context, name string) (*logical.Group, string, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, "", ErrNamespaceNotInContext
	}
	cg := s.namespaceIndex(ns.ID).groupsByName[name]
	if cg == nil {
		return nil, "", ErrGroupNotFound
	}
	return cg.Group.Clone(), cg.hash, nil
}

// ListGroups returns copies of the groups of the namespace in ctx, sorted by
// name, with their hashes. A non-empty role keeps only the groups listing it.
func (s *IdentityStore) ListGroups(ctx context.Context, role string) ([]*logical.Group, []string, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, nil, ErrNamespaceNotInContext
	}
	gs := s.namespaceIndex(ns.ID)
	names := make([]string, 0, len(gs.groupsByName))
	for name, cg := range gs.groupsByName {
		if role == "" || slices.Contains(cg.Roles, role) {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	groups := make([]*logical.Group, len(names))
	hashes := make([]string, len(names))
	for i, name := range names {
		cg := gs.groupsByName[name]
		groups[i], hashes[i] = cg.Group.Clone(), cg.hash
	}
	return groups, hashes, nil
}

// CreateGroup stores a new group in the namespace in ctx. g is normalized in
// place and receives its ID and timestamps; the store keeps its own copy. The
// returned warnings name roles that do not exist yet and selectors or mounts
// nothing in the namespace answers.
func (s *IdentityStore) CreateGroup(ctx context.Context, g *logical.Group) ([]string, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, ErrNamespaceNotInContext
	}
	cg, warnings, err := s.validateGroup(ctx, ns, g)
	if err != nil {
		return nil, err
	}
	id, err := uuid.GenerateUUID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate group id: %w", err)
	}

	err = func() error {
		s.mu.Lock()
		defer s.mu.Unlock()

		if err := s.writableLocked(); err != nil {
			return err
		}
		cur := s.namespaceIndex(ns.ID)
		if cur.groupsByName[g.Name] != nil {
			return ErrGroupAlreadyExists
		}
		// The caps bound what recomputes evaluate: virtual groups only.
		if max := int(s.maxVirtualGroups.Load()); g.Type == logical.GroupTypeVirtual && len(cur.virtualGroups) >= max {
			return fmt.Errorf("%w: the namespace has %d/%d virtual groups", ErrTooManyVirtualGroups, len(cur.virtualGroups), max)
		}
		if err := s.checkSelectorsLocked(cur, nil, cg); err != nil {
			return err
		}

		now := time.Now().UTC()
		g.ID, g.CreatedAt, g.UpdatedAt = id, now, now
		if err := s.commitLocked(ctx, ns, cur, g, cg); err != nil {
			return err
		}
		return nil
	}()
	if err != nil {
		return nil, err
	}
	s.logger.Info("created group",
		logger.String("namespace", ns.Path),
		logger.String("name", g.Name))
	return warnings, nil
}

// UpdateGroup replaces a group in the namespace in ctx with g, keeping its ID,
// type and creation time. When expectedHash is set the write is refused with
// ErrGroupChanged unless the stored group still has that hash. g is normalized
// in place and receives its ID and timestamps. A g.Type that differs from the
// stored type is refused: a group's membership source never changes.
func (s *IdentityStore) UpdateGroup(ctx context.Context, g *logical.Group, expectedHash string) ([]string, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, ErrNamespaceNotInContext
	}
	cg, warnings, err := s.validateGroup(ctx, ns, g)
	if err != nil {
		return nil, err
	}
	if s.beforeGroupUpdate != nil {
		s.beforeGroupUpdate()
	}

	err = func() error {
		s.mu.Lock()
		defer s.mu.Unlock()

		if err := s.writableLocked(); err != nil {
			return err
		}
		cur := s.namespaceIndex(ns.ID)
		old := cur.groupsByName[g.Name]
		if old == nil {
			return ErrGroupNotFound
		}
		if expectedHash != "" && old.hash != expectedHash {
			return ErrGroupChanged
		}
		if g.Type != old.Type {
			return &GroupTypeMismatchError{Name: g.Name, Stored: old.Type}
		}
		if err := s.checkSelectorsLocked(cur, old, cg); err != nil {
			return err
		}
		g.ID, g.CreatedAt, g.UpdatedAt = old.ID, old.CreatedAt, time.Now().UTC()
		return s.commitLocked(ctx, ns, cur, g, cg)
	}()
	if err != nil {
		return nil, err
	}
	s.logger.Info("updated group",
		logger.String("namespace", ns.Path),
		logger.String("name", g.Name))
	return warnings, nil
}

// checkSelectorsLocked refuses a write that would take the namespace past its
// cap on the selectors of virtual groups' rules: cur's total, less old's
// selectors (the group replaced, if any), plus next's. Caller holds mu.
func (s *IdentityStore) checkSelectorsLocked(cur *nsIndex, old, next *groupEntry) error {
	total := cur.selectors + next.selectors()
	if old != nil {
		total -= old.selectors()
	}
	if maxSelectors := int(s.maxSelectors.Load()); total > maxSelectors {
		return fmt.Errorf("%w: this write would make %d/%d virtual selectors (currently %d; every key of every rule counts, \"mount\" included)",
			ErrTooManySelectors, total, maxSelectors, cur.selectors)
	}
	return nil
}

// commitLocked stores g and publishes it with its compiled form cg in place of
// any group of the same name. Caller holds mu; cur is the namespace as
// published.
func (s *IdentityStore) commitLocked(ctx context.Context, ns *namespace.Namespace, cur *nsIndex, g *logical.Group, cg *groupEntry) error {
	stored := g.Clone()
	cg.Group, cg.hash = stored, stored.Hash()
	if err := s.persistGroup(ctx, ns.UUID, cg); err != nil {
		return err
	}
	byName := make(map[string]*groupEntry, len(cur.groupsByName)+1)
	for k, v := range cur.groupsByName {
		byName[k] = v
	}
	byName[g.Name] = cg
	s.publishGroupsLocked(ns.ID, byName)
	return nil
}

// DeleteGroup removes a group from the namespace in ctx. A non-empty t must be
// the stored type, checked under the lock so that a group deleted and
// recreated with another type between the caller's read and this write is
// refused. expectedHash makes the delete conditional, as for UpdateGroup.
func (s *IdentityStore) DeleteGroup(ctx context.Context, name string, t logical.GroupType, expectedHash string) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return ErrNamespaceNotInContext
	}

	err = func() error {
		s.mu.Lock()
		defer s.mu.Unlock()

		if err := s.writableLocked(); err != nil {
			return err
		}
		cur := s.namespaceIndex(ns.ID)
		old := cur.groupsByName[name]
		if old == nil {
			return ErrGroupNotFound
		}
		if t != "" && old.Type != t {
			return &GroupTypeMismatchError{Name: name, Stored: old.Type}
		}
		if expectedHash != "" && old.hash != expectedHash {
			return ErrGroupChanged
		}
		if err := s.storage.Delete(ctx, groupStorageKey(ns.UUID, old.ID)); err != nil {
			return fmt.Errorf("failed to delete group %q: %w", name, err)
		}
		byName := make(map[string]*groupEntry, len(cur.groupsByName))
		for k, v := range cur.groupsByName {
			if k != name {
				byName[k] = v
			}
		}
		s.publishGroupsLocked(ns.ID, byName)
		return nil
	}()
	if err != nil {
		return err
	}
	s.logger.Info("deleted group",
		logger.String("namespace", ns.Path),
		logger.String("name", name))
	return nil
}

// clearGroupsLocked deletes every stored group of the namespace and returns
// how many it deleted. Caller holds mu.
func (s *IdentityStore) clearGroupsLocked(ctx context.Context, nsUUID string) (int, error) {
	ids, err := s.storage.List(ctx, groupListPrefix(nsUUID))
	if err != nil {
		return 0, fmt.Errorf("failed to list groups for namespace cleanup: %w", err)
	}
	for _, id := range ids {
		if err := s.storage.Delete(ctx, groupStorageKey(nsUUID, id)); err != nil {
			return 0, fmt.Errorf("failed to delete group %s during namespace cleanup: %w", id, err)
		}
	}
	return len(ids), nil
}

// persistGroup writes cg's group to storage. Caller holds mu.
func (s *IdentityStore) persistGroup(ctx context.Context, nsUUID string, cg *groupEntry) error {
	data, err := json.Marshal(&StoredGroup{Version: storedGroupVersion, Group: cg.Group, Hash: cg.hash})
	if err != nil {
		return fmt.Errorf("failed to marshal group: %w", err)
	}
	if err := s.storage.Put(ctx, &sdklogical.StorageEntry{
		Key:   groupStorageKey(nsUUID, cg.ID),
		Value: data,
	}); err != nil {
		return fmt.Errorf("failed to write group %q: %w", cg.Name, err)
	}
	return nil
}

// loadGroupsLocked reads the stored groups of a namespace, by name. A listing
// that fails fails the load; a record that does not decode or compile, or
// whose name another record of the namespace already holds, is logged and
// skipped. Caller holds mu.
func (s *IdentityStore) loadGroupsLocked(ctx context.Context, ns *namespace.Namespace) (map[string]*groupEntry, error) {
	ids, err := s.storage.List(ctx, groupListPrefix(ns.UUID))
	if err != nil {
		return nil, fmt.Errorf("failed to list groups of namespace %q: %w", ns.Path, err)
	}
	byName := make(map[string]*groupEntry, len(ids))
	for _, id := range ids {
		cg, err := s.readGroup(ctx, ns.UUID, id)
		if err != nil {
			s.logger.Warn("skipping a stored group that cannot be read",
				logger.String("namespace", ns.Path),
				logger.String("id", id),
				logger.Err(err))
			continue
		}
		if prev := byName[cg.Name]; prev != nil {
			s.logger.Warn("skipping a stored group whose name another group holds",
				logger.String("namespace", ns.Path),
				logger.String("name", cg.Name),
				logger.String("id", id),
				logger.String("kept_id", prev.ID))
			continue
		}
		byName[cg.Name] = cg
	}
	return byName, nil
}

// readGroup reads, decodes and compiles one stored group.
func (s *IdentityStore) readGroup(ctx context.Context, nsUUID, id string) (*groupEntry, error) {
	entry, err := s.storage.Get(ctx, groupStorageKey(nsUUID, id))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, ErrGroupNotFound
	}
	var stored StoredGroup
	if err := json.Unmarshal(entry.Value, &stored); err != nil {
		return nil, fmt.Errorf("failed to decode: %w", err)
	}
	if stored.Version != storedGroupVersion {
		return nil, fmt.Errorf("unknown storage version %d", stored.Version)
	}
	if stored.Group == nil || stored.Group.ID != id || !validSysName(stored.Group.Name) {
		return nil, fmt.Errorf("record does not hold group %q", id)
	}
	if stored.Group.Type != logical.GroupTypeVirtual {
		return nil, fmt.Errorf("group type %q is not supported", stored.Group.Type)
	}
	// Published like a written group: as a clone, with no spare capacity left
	// behind by the decoder.
	g := stored.Group.Clone()
	cg, err := compileGroup(g)
	if err != nil {
		return nil, err
	}
	cg.Group, cg.hash = g, stored.Hash
	if cg.hash == "" {
		cg.hash = g.Hash()
	}
	return cg, nil
}

// validateGroup normalizes g in place, checks it and compiles it. It reads the
// role store and the auth mounts, so it runs before mu is taken. A role that
// does not exist, or a fact or mount nothing in the namespace answers, is a
// warning, not an error: either may be created after the group.
func (s *IdentityStore) validateGroup(ctx context.Context, ns *namespace.Namespace, g *logical.Group) (*groupEntry, []string, error) {
	if g == nil {
		return nil, nil, logical.ErrBadRequest("group is required")
	}
	if !validSysName(g.Name) {
		return nil, nil, logical.ErrBadRequestf("invalid group name %q: %s", g.Name, sysNameRule)
	}
	switch g.Type {
	case "":
		return nil, nil, logical.ErrBadRequestf("type is required: %q", logical.GroupTypeVirtual)
	case logical.GroupTypeVirtual:
	default:
		if _, err := logical.ParseGroupType(string(g.Type)); err != nil {
			return nil, nil, logical.ErrBadRequest(err.Error())
		}
		return nil, nil, logical.ErrBadRequestf("group type %q is not supported yet; only %q groups can be created",
			g.Type, logical.GroupTypeVirtual)
	}
	if len(g.Description) > logical.MaxGroupDescriptionBytes {
		return nil, nil, logical.ErrBadRequestf("description exceeds %d bytes", logical.MaxGroupDescriptionBytes)
	}
	if err := validateObjectMetadata(g.Metadata); err != nil {
		return nil, nil, err
	}
	if len(g.Metadata) == 0 {
		g.Metadata = nil
	}
	// Stored as an instant in UTC, as it renders.
	if !g.ValidUntil.IsZero() {
		g.ValidUntil = g.ValidUntil.Round(0).UTC()
	}

	roles, err := normalizeGroupRoles(g.Roles)
	if err != nil {
		return nil, nil, err
	}
	g.Roles = roles

	if len(g.Rules) == 0 {
		return nil, nil, logical.ErrBadRequest("a virtual group needs at least one rule")
	}
	if len(g.Rules) > logical.MaxGroupRules {
		return nil, nil, logical.ErrBadRequestf("a group has at most %d rules, got %d",
			logical.MaxGroupRules, len(g.Rules))
	}
	cg, err := compileGroup(g)
	if err != nil {
		return nil, nil, logical.ErrBadRequest(err.Error())
	}

	var warnings []string
	if !g.ValidUntil.IsZero() && time.Now().After(g.ValidUntil) {
		warnings = append(warnings, "valid_until is in the past; the group grants nothing")
	}
	if s.core.roleStore != nil {
		roleSnap := s.core.roleStore.snapshot.Load()
		for _, r := range g.Roles {
			if roleSnap.lookup(ns.ID, r) == nil {
				warnings = append(warnings, fmt.Sprintf("role %q does not exist yet; the group grants it once it does", r))
			}
		}
	}
	warnings = append(warnings, ruleWarnings(g, s.core.namespaceAuthMountFacts(ctx))...)
	return cg, warnings, nil
}

// normalizeGroupRoles returns roles sorted and deduplicated, refusing a name
// that cannot name a role and more than MaxGroupRoles of them.
func normalizeGroupRoles(roles []string) ([]string, error) {
	out := make([]string, 0, len(roles))
	for _, r := range roles {
		if !validSysName(r) {
			return nil, logical.ErrBadRequestf("invalid role name %q in roles: %s", r, sysNameRule)
		}
		out = append(out, r)
	}
	slices.Sort(out)
	out = slices.Clip(slices.Compact(out))
	if len(out) > logical.MaxGroupRoles {
		return nil, logical.ErrBadRequestf("a group grants at most %d roles, got %d", logical.MaxGroupRoles, len(out))
	}
	return out, nil
}

// authMountFacts is what a group write needs to know about one auth mount of
// its namespace.
type authMountFacts struct {
	path  string   // namespace-relative, "auth/<path>/": what "mount" answers
	names []string // the fact names the mount answers; nil when it publishes none
}

// namespaceAuthMountFacts lists the auth mounts of the namespace in ctx with
// the fact names each answers (logical.FactsProvider, reached through the
// router). Called at group write only, never on the request path.
func (c *Core) namespaceAuthMountFacts(ctx context.Context) []authMountFacts {
	var paths []string
	c.authLock.RLock()
	if c.auth != nil {
		if entries, err := c.auth.findAllNamespaceMounts(ctx); err == nil {
			for _, e := range entries {
				if !e.Tainted {
					paths = append(paths, authRoutePrefix+e.Path)
				}
			}
		}
	}
	c.authLock.RUnlock()

	out := make([]authMountFacts, 0, len(paths))
	for _, path := range paths {
		m := authMountFacts{path: path}
		if c.router != nil {
			if fp, ok := c.router.MatchingBackend(ctx, path).(logical.FactsProvider); ok {
				m.names = fp.FactNames()
			}
		}
		out = append(out, m)
	}
	return out
}

// ruleWarnings checks each rule of g against the namespace's auth mounts: the
// mounts its "mount" selector lists must exist, and the fact every other
// selector names must be answered by at least one of them. Facts are checked
// only against the mounts the rule lists, since only those can ever match it.
func ruleWarnings(g *logical.Group, mounts []authMountFacts) []string {
	var warnings []string
	for i, rule := range g.Rules {
		listed := map[int]bool{}
		literalMiss := false
		for _, v := range rule[selector.NameMount] {
			if selector.IsPattern(v) {
				if strings.Contains(v, "**") {
					warnings = append(warnings, fmt.Sprintf(
						`rules[%d]: mount %q uses "**", which matches across "/": it trusts every auth mount it reaches, including ones enabled later`, i, v))
				}
				gl, err := selector.CompileGlob(v)
				if err != nil {
					continue
				}
				for j, m := range mounts {
					if gl.Match(m.path) {
						listed[j] = true
					}
				}
				continue
			}
			lit, err := selector.Unescape(v)
			if err != nil {
				continue
			}
			found := false
			for j, m := range mounts {
				if m.path == lit {
					listed[j], found = true, true
				}
			}
			if !found {
				literalMiss = true
				warnings = append(warnings, fmt.Sprintf(
					"rules[%d]: mount %q names no auth mount in this namespace; the rule cannot match through it until one is enabled there", i, v))
			}
		}
		if len(listed) == 0 {
			if !literalMiss {
				warnings = append(warnings, fmt.Sprintf(
					`rules[%d]: no auth mount in this namespace matches the rule's "mount" selector`, i))
			}
			continue
		}

		for _, name := range slices.Sorted(maps.Keys(rule)) {
			switch name {
			case selector.NameMount:
				continue
			case selector.NameKind:
				for _, v := range rule[name] {
					if !selector.IsPattern(v) && v != logical.EntityKindAgent && v != logical.EntityKindHuman {
						warnings = append(warnings, fmt.Sprintf(
							`rules[%d]: the "kind" selector's value %q is neither %q nor %q and never matches`, i, v,
							logical.EntityKindAgent, logical.EntityKindHuman))
					}
				}
				continue
			}
			produced := false
			for j := range listed {
				if slices.Contains(mounts[j].names, name) {
					produced = true
					break
				}
			}
			if !produced {
				warnings = append(warnings, fmt.Sprintf(
					"rules[%d]: no auth mount the rule lists produces fact %q; its selector cannot match until one maps it", i, name))
			}
		}
	}
	return warnings
}
