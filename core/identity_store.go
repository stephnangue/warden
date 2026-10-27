package core

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"

	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

var ErrIdentityStoreNotLoaded = errors.New("identity store is not loaded")

// Storage layout: every record of the identity store is under the barrier view
// at identityStorePath, grouped by namespace UUID: the groups under
// {namespace-uuid}/group/ (identity_groups.go) and the entities under
// {namespace-uuid}/entity/ (identity_entities.go).
const identityStorePath = "core/identity/"

// IdentityStore holds the namespace groups and entities: durable records in
// storage and an in-memory snapshot, compiled and indexed (one nsIndex per
// namespace), that serves every read and every membership computation.
//
// # Thread safety
//
// Readers never lock. They load the snapshot pointer once and read from it; a
// published snapshot, its namespaces, their indexes and the groups and
// entities they hold are never written again. A write builds the next
// namespace value and swaps the snapshot in: a group write clones the
// namespace's group map and rebuilds its mount index, an entity write commits
// one transaction per entity tree; the other half, and every other namespace,
// is shared by pointer. A reader holding an older snapshot keeps seeing it
// whole.
//
// mu serializes writers and guards storage and loaded. Each mutator validates
// holding no lock (a group's validation reads the role store and asks the auth
// mounts for their fact names), then commits under mu: the existence, count,
// uniqueness and expected-hash checks, the storage write and the publish.
//
// gen is the store-wide publish counter. Every publish of a namespace takes
// the next value, so a namespace's generation changes exactly when its groups
// or entities do, and a publish in one namespace leaves every other
// namespace's generation, and the memberships computed from it, as they were.
// It is never reset, not even across Unload and Load, so a generation never
// names two different states of one namespace.
//
// # Lifecycle
//
// Load runs on the active node only, after the mounts are set up; Unload drops
// the snapshot when the node seals or steps down. Until Load runs every read
// answers "not found", every namespace has no groups and no entities, and
// every write is refused.
type IdentityStore struct {
	core   *Core
	logger *logger.GatedLogger

	snapshot atomic.Pointer[identitySnapshot]
	gen      atomic.Uint64

	mu      sync.Mutex
	storage sdklogical.Storage // barrier view at identityStorePath
	loaded  bool

	// maxVirtualGroups and maxSelectors are the namespace caps a write checks
	// and Usage reports: logical.MaxVirtualGroupsPerNamespace and
	// logical.MaxSelectorsPerNamespace, lowered by tests only. Atomic, so Usage
	// reads them without taking mu.
	maxVirtualGroups, maxSelectors atomic.Int64

	// beforeGroupUpdate, when set, runs in UpdateGroup after validation and
	// before the commit. Nil outside tests.
	beforeGroupUpdate func()
}

// NewIdentityStore constructs the store. Storage is wired up by Load once the
// barrier is unsealed.
func NewIdentityStore(c *Core) *IdentityStore {
	s := &IdentityStore{
		core:   c,
		logger: c.logger.WithSystem("identity.store"),
	}
	s.maxVirtualGroups.Store(logical.MaxVirtualGroupsPerNamespace)
	s.maxSelectors.Store(logical.MaxSelectorsPerNamespace)
	s.snapshot.Store(emptyIdentitySnapshot)
	return s
}

// namespaceIndex returns the published index of namespace nsID (its groups
// and entities), or emptyNSIndex when it has neither. Lock-free; does not
// allocate.
func (s *IdentityStore) namespaceIndex(nsID string) *nsIndex {
	return s.snapshot.Load().namespace(nsID)
}

// IdentityUsage is a namespace's identity objects counted by kind, against
// their caps. Each kind is one top-level key.
type IdentityUsage struct {
	Groups     GroupsUsage     `json:"groups"`
	Identities IdentitiesUsage `json:"identities"`
}

// IdentitiesUsage counts a namespace's entities, against
// MaxEntitiesPerNamespace, and the native identities they claim.
type IdentitiesUsage struct {
	Entities    int `json:"entities"`
	MaxEntities int `json:"max_entities"`
	Aliases     int `json:"aliases"`
}

// GroupsUsage counts a namespace's groups: all of them, then by type, each
// type with the caps that apply to it.
type GroupsUsage struct {
	Total   int                `json:"total"`
	Virtual VirtualGroupsUsage `json:"virtual"`
}

// VirtualGroupsUsage counts a namespace's virtual groups and the selectors of
// their rules ("mount" included), against MaxVirtualGroupsPerNamespace and
// MaxSelectorsPerNamespace.
type VirtualGroupsUsage struct {
	Count        int `json:"count"`
	Max          int `json:"max"`
	Selectors    int `json:"selectors"`
	MaxSelectors int `json:"max_selectors"`
}

// Usage reports the identity usage of the namespace in ctx. It reads one
// snapshot, takes no lock and reads no storage.
func (s *IdentityStore) Usage(ctx context.Context) (IdentityUsage, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return IdentityUsage{}, ErrNamespaceNotInContext
	}
	gs := s.namespaceIndex(ns.ID)
	return IdentityUsage{
		Groups: GroupsUsage{
			Total: len(gs.groupsByName),
			Virtual: VirtualGroupsUsage{
				Count:        len(gs.virtualGroups),
				Max:          int(s.maxVirtualGroups.Load()),
				Selectors:    gs.selectors,
				MaxSelectors: int(s.maxSelectors.Load()),
			},
		},
		Identities: IdentitiesUsage{
			Entities:    gs.entities.count(),
			MaxEntities: logical.MaxEntitiesPerNamespace,
			Aliases:     gs.entities.aliasCount(),
		},
	}, nil
}

// Load reads every group and entity from storage, compiles and publishes them.
// Called on the active node during unseal, after the namespaces and mounts
// are loaded.
func (s *IdentityStore) Load(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.storage == nil {
		s.storage = NewBarrierView(s.core.barrier, identityStorePath)
	}
	start := time.Now()
	snap, count, err := s.loadAllLocked(ctx)
	if err != nil {
		return err
	}
	s.snapshot.Store(snap)
	s.loaded = true
	entities, aliases := 0, 0
	for _, g := range snap.byNS {
		entities += g.entities.count()
		aliases += g.entities.aliasCount()
	}
	s.logger.Info("identity store loaded",
		logger.Int("groups", count),
		logger.Int("entities", entities),
		logger.Int("aliases", aliases),
		logger.String("duration", time.Since(start).String()))
	return nil
}

// Unload drops the snapshot. The records stay in storage for the next Load.
func (s *IdentityStore) Unload() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.snapshot.Store(emptyIdentitySnapshot)
	s.loaded = false
}

func (s *IdentityStore) writableLocked() error {
	if !s.loaded || s.storage == nil {
		return ErrIdentityStoreNotLoaded
	}
	return nil
}

// loadAllLocked reads every stored group and entity into a new snapshot and
// returns it with the number of groups it holds. A listing that fails fails
// the load; records of a namespace that no longer exists are logged and
// skipped, and so is a record that cannot be loaded (loadGroupsLocked,
// loadEntitiesLocked). Caller holds mu.
func (s *IdentityStore) loadAllLocked(ctx context.Context) (*identitySnapshot, int, error) {
	nsKeys, err := s.storage.List(ctx, "")
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list identity namespaces: %w", err)
	}

	snap := &identitySnapshot{byNS: make(map[string]*nsIndex, len(nsKeys))}
	count := 0
	for _, nsKey := range nsKeys {
		nsUUID := strings.TrimSuffix(nsKey, "/")
		ns, err := s.core.namespaceStore.GetNamespace(ctx, nsUUID)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to resolve namespace %q of stored identity objects: %w", nsUUID, err)
		}
		if ns == nil {
			s.logger.Warn("skipping identity objects stored for a namespace that does not exist",
				logger.String("namespace_uuid", nsUUID))
			continue
		}
		byName, err := s.loadGroupsLocked(ctx, ns)
		if err != nil {
			return nil, 0, err
		}
		ents, err := s.loadEntitiesLocked(ctx, ns)
		if err != nil {
			return nil, 0, err
		}
		if g := buildNSIndex(byName, ents, s.gen.Add(1)); g != nil {
			snap.byNS[ns.ID] = g
			count += len(byName)
		}
	}
	return snap, count, nil
}

// ClearNamespace deletes every group and entity of the namespace in ctx, from
// storage and from the snapshot. Called during namespace deletion. It sweeps
// what storage holds, so a record the snapshot skipped at load is removed too.
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
	groups, err := s.clearGroupsLocked(ctx, ns.UUID)
	if err != nil {
		return err
	}
	entities, err := s.clearEntitiesLocked(ctx, ns.UUID)
	if err != nil {
		return err
	}
	if snap := s.snapshot.Load(); snap.byNS[ns.ID] != nil {
		s.snapshot.Store(snap.withNamespace(ns.ID, nil))
	}
	if groups > 0 || entities > 0 {
		s.logger.Info("cleared identity objects for namespace",
			logger.String("namespace", ns.UUID),
			logger.Int("groups_deleted", groups),
			logger.Int("entities_deleted", entities))
	}
	return nil
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
