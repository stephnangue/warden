package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/go-uuid"
	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/helper/selector"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

var (
	ErrIdentityStoreNotLoaded = errors.New("identity store is not loaded")
	ErrGroupNotFound          = errors.New("group not found")
	ErrGroupAlreadyExists     = errors.New("group already exists")
	ErrTooManyGroups          = errors.New("too many groups in the namespace")
	ErrTooManySelectors       = errors.New("too many selectors in the namespace")

	// ErrGroupChanged is returned by UpdateGroup and DeleteGroup when the
	// caller passed an expected hash and the stored group no longer has it.
	ErrGroupChanged = errors.New("group changed concurrently")
)

// Storage layout, under the barrier view at identityStorePath:
//
//	{namespace-uuid}/group/{id} -> JSON-encoded StoredGroup
//
// A group is stored under its ID, not its name, so that the identity objects
// added to this store later reference groups by a key that never changes.
const (
	identityStorePath  = "core/identity/"
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

// IdentityStore holds the namespace groups: durable records in storage and an
// in-memory snapshot, compiled and indexed, that serves every read and every
// membership computation.
//
// # Thread safety
//
// Readers never lock. They load the snapshot pointer once and read from it; a
// published snapshot, its namespaces, their indexes and the groups they hold
// are never written again. A write builds the next namespace value (cloning
// the namespace's name map and rebuilding its index, other namespaces shared
// by pointer) and swaps the snapshot in. A reader holding an older snapshot
// keeps seeing it whole.
//
// mu serializes writers and guards storage and loaded. Each mutator validates
// holding no lock (validation reads the role store and asks the auth mounts
// for their fact names), then commits under mu: the existence, count and
// expected-hash checks, the storage write and the publish.
//
// gen is the store-wide publish counter. Every publish of a namespace takes
// the next value, so a namespace's generation changes exactly when its groups
// do, and a publish in one namespace leaves every other namespace's generation,
// and the memberships computed from it, as they were. It is never reset, not
// even across Unload and Load, so a generation never names two different
// states of one namespace.
//
// # Lifecycle
//
// Load runs on the active node only, after the mounts are set up; Unload drops
// the snapshot when the node seals or steps down. Until Load runs every read
// answers "not found", every namespace has no groups, and every write is
// refused.
type IdentityStore struct {
	core   *Core
	logger *logger.GatedLogger

	groups atomic.Pointer[groupSnapshot]
	gen    atomic.Uint64

	mu      sync.Mutex
	storage sdklogical.Storage // barrier view at identityStorePath
	loaded  bool

	// maxGroups and maxSelectors are the namespace caps a write checks:
	// logical.MaxGroupsPerNamespace and logical.MaxSelectorsPerNamespace,
	// lowered by tests only. Read and written under mu.
	maxGroups, maxSelectors int

	// beforeGroupUpdate, when set, runs in UpdateGroup after validation and
	// before the commit. Nil outside tests.
	beforeGroupUpdate func()
}

// NewIdentityStore constructs the store. Storage is wired up by Load once the
// barrier is unsealed.
func NewIdentityStore(c *Core) *IdentityStore {
	s := &IdentityStore{
		core:         c,
		logger:       c.logger.WithSystem("identity.store"),
		maxGroups:    logical.MaxGroupsPerNamespace,
		maxSelectors: logical.MaxSelectorsPerNamespace,
	}
	s.groups.Store(emptyGroupSnapshot)
	return s
}

// namespaceGroups returns the published groups of namespace nsID, or the
// empty namespace when it has none. Lock-free; does not allocate.
func (s *IdentityStore) namespaceGroups(nsID string) *nsGroups {
	return s.groups.Load().namespace(nsID)
}

// GroupsListingRole returns the names of the groups of namespace nsID that
// list role, sorted.
func (s *IdentityStore) GroupsListingRole(nsID, role string) []string {
	return s.namespaceGroups(nsID).listing(role)
}

// publishLocked makes byName the namespace's groups under the next generation.
// Caller holds mu and hands over byName.
func (s *IdentityStore) publishLocked(nsID string, byName map[string]*compiledGroup) {
	snap := s.groups.Load()
	s.groups.Store(snap.withNamespace(nsID, buildNSGroups(byName, s.gen.Add(1))))
}

// Load reads every group from storage, compiles and publishes them. Called on
// the active node during unseal, after the namespaces and mounts are loaded.
func (s *IdentityStore) Load(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.storage == nil {
		s.storage = NewBarrierView(s.core.barrier, identityStorePath)
	}
	snap, count, err := s.loadAllLocked(ctx)
	if err != nil {
		return err
	}
	s.groups.Store(snap)
	s.loaded = true
	s.logger.Debug("identity store loaded", logger.Int("groups", count))
	return nil
}

// Unload drops the snapshot. The records stay in storage for the next Load.
func (s *IdentityStore) Unload() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.groups.Store(emptyGroupSnapshot)
	s.loaded = false
}

func (s *IdentityStore) writableLocked() error {
	if !s.loaded || s.storage == nil {
		return ErrIdentityStoreNotLoaded
	}
	return nil
}

// GetGroup returns a copy of the group name in the namespace in ctx, and the
// hash a conditional write passes back.
func (s *IdentityStore) GetGroup(ctx context.Context, name string) (*logical.Group, string, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, "", ErrNamespaceNotInContext
	}
	cg := s.namespaceGroups(ns.ID).byName[name]
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
	gs := s.namespaceGroups(ns.ID)
	names := make([]string, 0, len(gs.byName))
	for name, cg := range gs.byName {
		if role == "" || slices.Contains(cg.Roles, role) {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	groups := make([]*logical.Group, len(names))
	hashes := make([]string, len(names))
	for i, name := range names {
		cg := gs.byName[name]
		groups[i], hashes[i] = cg.Group.Clone(), cg.hash
	}
	return groups, hashes, nil
}

// CreateGroup stores a new group in the namespace in ctx. g is normalized in
// place and receives its ID and timestamps; the store keeps its own copy. The
// returned warnings name roles that do not exist yet and selector facts or
// mounts nothing in the namespace answers.
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
		cur := s.namespaceGroups(ns.ID)
		if cur.byName[g.Name] != nil {
			return ErrGroupAlreadyExists
		}
		if len(cur.byName) >= s.maxGroups {
			return fmt.Errorf("%w: a namespace holds at most %d groups", ErrTooManyGroups, s.maxGroups)
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
		cur := s.namespaceGroups(ns.ID)
		old := cur.byName[g.Name]
		if old == nil {
			return ErrGroupNotFound
		}
		if expectedHash != "" && old.hash != expectedHash {
			return ErrGroupChanged
		}
		if g.Type != old.Type {
			return errGroupTypeChange
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

var errGroupTypeChange = logical.ErrBadRequest("type cannot change; create a new group")

// checkSelectorsLocked refuses a write that would take the namespace past its
// selector cap: cur's total, less old's selectors (the group replaced, if
// any), plus next's. Caller holds mu.
func (s *IdentityStore) checkSelectorsLocked(cur *nsGroups, old, next *compiledGroup) error {
	total := cur.selectors + len(next.rules)
	if old != nil {
		total -= len(old.rules)
	}
	if total > s.maxSelectors {
		return fmt.Errorf("%w: the groups of a namespace hold at most %d selectors together; this write would make %d",
			ErrTooManySelectors, s.maxSelectors, total)
	}
	return nil
}

// commitLocked stores g and publishes it with its compiled form cg in place of
// any group of the same name. Caller holds mu; cur is the namespace as
// published.
func (s *IdentityStore) commitLocked(ctx context.Context, ns *namespace.Namespace, cur *nsGroups, g *logical.Group, cg *compiledGroup) error {
	stored := g.Clone()
	cg.Group, cg.hash = stored, stored.Hash()
	if err := s.persistGroup(ctx, ns.UUID, cg); err != nil {
		return err
	}
	byName := make(map[string]*compiledGroup, len(cur.byName)+1)
	for k, v := range cur.byName {
		byName[k] = v
	}
	byName[g.Name] = cg
	s.publishLocked(ns.ID, byName)
	return nil
}

// DeleteGroup removes a group from the namespace in ctx. expectedHash makes it
// conditional, as for UpdateGroup.
func (s *IdentityStore) DeleteGroup(ctx context.Context, name, expectedHash string) error {
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
		cur := s.namespaceGroups(ns.ID)
		old := cur.byName[name]
		if old == nil {
			return ErrGroupNotFound
		}
		if expectedHash != "" && old.hash != expectedHash {
			return ErrGroupChanged
		}
		if err := s.storage.Delete(ctx, groupStorageKey(ns.UUID, old.ID)); err != nil {
			return fmt.Errorf("failed to delete group %q: %w", name, err)
		}
		byName := make(map[string]*compiledGroup, len(cur.byName))
		for k, v := range cur.byName {
			if k != name {
				byName[k] = v
			}
		}
		s.publishLocked(ns.ID, byName)
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

// ClearNamespace deletes every group of the namespace in ctx, from storage and
// from the snapshot. Called during namespace deletion. It sweeps what storage
// holds, so a record the snapshot skipped at load is removed too.
func (s *IdentityStore) ClearNamespace(ctx context.Context) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return ErrNamespaceNotInContext
	}

	// One critical section for the whole sweep: a create landing part-way
	// through would otherwise survive the namespace deletion.
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.storage == nil {
		return nil
	}
	ids, err := s.storage.List(ctx, groupListPrefix(ns.UUID))
	if err != nil {
		return fmt.Errorf("failed to list groups for namespace cleanup: %w", err)
	}
	for _, id := range ids {
		if err := s.storage.Delete(ctx, groupStorageKey(ns.UUID, id)); err != nil {
			return fmt.Errorf("failed to delete group %s during namespace cleanup: %w", id, err)
		}
	}
	if snap := s.groups.Load(); snap.byNS[ns.ID] != nil {
		s.groups.Store(snap.withNamespace(ns.ID, nil))
	}
	if len(ids) > 0 {
		s.logger.Info("cleared groups for namespace",
			logger.String("namespace", ns.UUID),
			logger.Int("groups_deleted", len(ids)))
	}
	return nil
}

// persistGroup writes cg's group to storage. Caller holds mu.
func (s *IdentityStore) persistGroup(ctx context.Context, nsUUID string, cg *compiledGroup) error {
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

// loadAllLocked reads every stored group into a new snapshot and returns it
// with the number of groups it holds. A listing that fails fails the load; a
// record that does not decode or compile, whose namespace no longer exists, or
// whose name another record of the namespace already holds, is logged and
// skipped. Caller holds mu.
func (s *IdentityStore) loadAllLocked(ctx context.Context) (*groupSnapshot, int, error) {
	nsKeys, err := s.storage.List(ctx, "")
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list identity namespaces: %w", err)
	}

	snap := &groupSnapshot{byNS: make(map[string]*nsGroups, len(nsKeys))}
	count := 0
	for _, nsKey := range nsKeys {
		nsUUID := strings.TrimSuffix(nsKey, "/")
		ns, err := s.core.namespaceStore.GetNamespace(ctx, nsUUID)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to resolve namespace %q of stored groups: %w", nsUUID, err)
		}
		if ns == nil {
			s.logger.Warn("skipping groups stored for a namespace that does not exist",
				logger.String("namespace_uuid", nsUUID))
			continue
		}

		ids, err := s.storage.List(ctx, groupListPrefix(nsUUID))
		if err != nil {
			return nil, 0, fmt.Errorf("failed to list groups of namespace %q: %w", ns.Path, err)
		}
		byName := make(map[string]*compiledGroup, len(ids))
		for _, id := range ids {
			cg, err := s.readGroup(ctx, nsUUID, id)
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
		if g := buildNSGroups(byName, s.gen.Add(1)); g != nil {
			snap.byNS[ns.ID] = g
			count += len(byName)
		}
	}
	return snap, count, nil
}

// readGroup reads, decodes and compiles one stored group.
func (s *IdentityStore) readGroup(ctx context.Context, nsUUID, id string) (*compiledGroup, error) {
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
func (s *IdentityStore) validateGroup(ctx context.Context, ns *namespace.Namespace, g *logical.Group) (*compiledGroup, []string, error) {
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
	if g.MaxAge < 0 {
		return nil, nil, logical.ErrBadRequest("max_age must not be negative")
	}

	roles, err := normalizeGroupRoles(g.Roles)
	if err != nil {
		return nil, nil, err
	}
	g.Roles = roles

	if len(g.Selectors) == 0 {
		return nil, nil, logical.ErrBadRequest("a virtual group needs at least one selector")
	}
	if len(g.Selectors) > logical.MaxGroupSelectors {
		return nil, nil, logical.ErrBadRequestf("a group has at most %d selectors, got %d",
			logical.MaxGroupSelectors, len(g.Selectors))
	}
	cg, err := compileGroup(g)
	if err != nil {
		return nil, nil, logical.ErrBadRequest(err.Error())
	}

	var warnings []string
	if s.core.roleStore != nil {
		roleSnap := s.core.roleStore.snapshot.Load()
		for _, r := range g.Roles {
			if roleSnap.lookup(ns.ID, r) == nil {
				warnings = append(warnings, fmt.Sprintf("role %q does not exist yet; the group grants it once it does", r))
			}
		}
	}
	warnings = append(warnings, selectorWarnings(g, s.core.namespaceAuthMountFacts(ctx))...)
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
	typ   string   // the auth method
	names []string // the fact names the mount answers; nil when it publishes none
}

// noIssuedAtMethods are the auth methods whose admissions never carry an issue
// time, so a group max_age never admits through them.
var noIssuedAtMethods = map[string]bool{"cert": true}

// namespaceAuthMountFacts lists the auth mounts of the namespace in ctx with
// the fact names each answers (logical.FactsProvider, reached through the
// router). Called at group write only, never on the request path.
func (c *Core) namespaceAuthMountFacts(ctx context.Context) []authMountFacts {
	type mountRef struct{ path, typ string }
	var refs []mountRef
	c.authLock.RLock()
	if c.auth != nil {
		if entries, err := c.auth.findAllNamespaceMounts(ctx); err == nil {
			for _, e := range entries {
				if !e.Tainted {
					refs = append(refs, mountRef{path: authRoutePrefix + e.Path, typ: e.Type})
				}
			}
		}
	}
	c.authLock.RUnlock()

	out := make([]authMountFacts, 0, len(refs))
	for _, r := range refs {
		m := authMountFacts{path: r.path, typ: r.typ}
		if c.router != nil {
			if fp, ok := c.router.MatchingBackend(ctx, r.path).(logical.FactsProvider); ok {
				m.names = fp.FactNames()
			}
		}
		out = append(out, m)
	}
	return out
}

// selectorWarnings checks each rule of g against the namespace's auth mounts:
// the mounts a rule lists must exist, and every other fact it names must be
// answered by at least one of them. Facts are checked only against the mounts
// the rule lists, since only those can ever match it.
func selectorWarnings(g *logical.Group, mounts []authMountFacts) []string {
	var warnings []string
	for i, s := range g.Selectors {
		listed := map[int]bool{}
		literalMiss := false
		for _, v := range s[selector.NameMount] {
			if selector.IsPattern(v) {
				if (len(v) >= 2 && strings.Trim(v, "*") == "") || v == "auth/**" {
					warnings = append(warnings, fmt.Sprintf(
						"selectors[%d]: mount %q trusts every auth mount in this namespace, including ones enabled later", i, v))
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
					"selectors[%d]: mount %q names no auth mount in this namespace; the rule cannot match through it until one is enabled there", i, v))
			}
		}
		if len(listed) == 0 {
			if !literalMiss {
				warnings = append(warnings, fmt.Sprintf(
					"selectors[%d]: no auth mount in this namespace matches the rule's mount patterns", i))
			}
			continue
		}

		for _, name := range slices.Sorted(maps.Keys(s)) {
			switch name {
			case selector.NameMount:
				continue
			case selector.NameKind:
				for _, v := range s[name] {
					if !selector.IsPattern(v) && v != logical.EntityKindAgent && v != logical.EntityKindHuman {
						warnings = append(warnings, fmt.Sprintf(
							"selectors[%d]: kind %q is neither %q nor %q and never matches", i, v,
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
					"selectors[%d]: no auth mount the rule lists produces fact %q; the rule cannot match until one maps it", i, name))
			}
		}

		if g.MaxAge > 0 {
			allNoIssuedAt := true
			var paths []string
			for j := range listed {
				paths = append(paths, mounts[j].path)
				if !noIssuedAtMethods[mounts[j].typ] {
					allNoIssuedAt = false
				}
			}
			if allNoIssuedAt {
				slices.Sort(paths)
				warnings = append(warnings, fmt.Sprintf(
					"selectors[%d]: max_age never matches this rule: its mounts (%s) admit credentials that carry no issue time",
					i, strings.Join(paths, ", ")))
			}
		}
	}
	return warnings
}

// setupIdentityStore wires the identity store to the unsealed barrier and, on
// the active node, loads it. A standby loads nothing: it forwards every
// request, and it loads when it becomes active.
func (c *Core) setupIdentityStore(ctx context.Context, standby bool) error {
	if c.identityStore == nil {
		return fmt.Errorf("identity store not initialized")
	}
	if standby {
		return nil
	}
	return c.identityStore.Load(ctx)
}

// teardownIdentityStore is the seal-time inverse of setupIdentityStore.
func (c *Core) teardownIdentityStore() {
	if c.identityStore != nil {
		c.identityStore.Unload()
	}
}
