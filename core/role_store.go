package core

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	authhelper "github.com/stephnangue/warden/auth/helper"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

var (
	ErrRoleStoreNotLoaded = errors.New("role store is not loaded")
	ErrRoleNotFound       = errors.New("role not found")
	ErrRoleAlreadyExists  = errors.New("role already exists")

	// ErrRoleChanged is returned by Update and Delete when the caller passed an
	// expected hash and the stored role no longer has it: another writer got
	// there first, and applying this write would undo theirs.
	ErrRoleChanged = errors.New("role changed concurrently")
)

// RoleStore holds the namespace roles: durable records in storage and an
// in-memory snapshot that serves every read.
//
// # Thread safety
//
// Readers never lock. They load the snapshot pointer once and read from it; a
// published snapshot, its maps and the roles it holds are never written again.
// A write builds the next snapshot, cloning only the outer map and the map of
// the namespace it touches (other namespaces are shared by pointer), and swaps
// it in. A reader holding an older snapshot keeps seeing it whole.
//
// mu serializes writers and guards storage and loaded. Each mutator
// validates holding no lock (validation reads the policy and credential stores),
// then commits under mu: the existence and expected-hash checks, the storage
// write and the publish. Nothing but logging happens after the unlock.
//
// # Lifecycle
//
// Load runs on the active node only, after the mounts are set up; Unload drops
// the snapshot when the node seals or steps down, and the next active node loads
// again. Until Load runs (a standby, a sealed node) every read answers "not
// found" and every write is refused.
type RoleStore struct {
	core   *Core
	logger *logger.GatedLogger

	snapshot atomic.Pointer[roleSnapshot]

	mu      sync.Mutex
	storage sdklogical.Storage // barrier view at roleStorePath
	loaded  bool

	// beforeUpdate, when set, runs in Update after validation and before the
	// commit. Nil outside tests: it lets a test land a concurrent write between
	// an update's read and its commit.
	beforeUpdate func()
}

// roleSnapshot is one published state of every namespace's roles, keyed by
// namespace ID (the accessor tokens carry). Immutable once published.
type roleSnapshot struct {
	byNS map[string]*nsRoles
}

// nsRoles is one namespace's roles. Immutable once published.
type nsRoles struct {
	byName map[string]*roleEntry
}

// roleEntry is a published role and the hash it was stored with.
type roleEntry struct {
	role *logical.Role
	hash string
}

// emptyRoleSnapshot is what an unloaded store serves.
var emptyRoleSnapshot = &roleSnapshot{}

// NewRoleStore constructs the store. Storage is wired up by Load once the
// barrier is unsealed.
func NewRoleStore(c *Core) *RoleStore {
	s := &RoleStore{
		core:   c,
		logger: c.logger.WithSystem("role.store"),
	}
	s.snapshot.Store(emptyRoleSnapshot)
	return s
}

// lookup returns the published role, or nil. The role is shared: callers must
// not write to it. It takes no lock and does not allocate.
func (s *roleSnapshot) lookup(nsID, name string) *roleEntry {
	nr := s.byNS[nsID]
	if nr == nil {
		return nil
	}
	return nr.byName[name]
}

// withEntry returns a snapshot in which namespace nsID holds e under name, or no
// role under name when e is nil. s is left as it was.
func (s *roleSnapshot) withEntry(nsID, name string, e *roleEntry) *roleSnapshot {
	var next map[string]*roleEntry
	if old := s.byNS[nsID]; old != nil {
		next = make(map[string]*roleEntry, len(old.byName)+1)
		for k, v := range old.byName {
			next[k] = v
		}
	} else {
		next = make(map[string]*roleEntry, 1)
	}
	if e != nil {
		next[name] = e
	} else {
		delete(next, name)
	}
	if len(next) == 0 {
		return s.withNamespace(nsID, nil)
	}
	return s.withNamespace(nsID, &nsRoles{byName: next})
}

// withNamespace returns a snapshot in which namespace nsID holds nr, or nothing
// when nr is nil. s is left as it was.
func (s *roleSnapshot) withNamespace(nsID string, nr *nsRoles) *roleSnapshot {
	byNS := make(map[string]*nsRoles, len(s.byNS)+1)
	for k, v := range s.byNS {
		byNS[k] = v
	}
	if nr != nil {
		byNS[nsID] = nr
	} else {
		delete(byNS, nsID)
	}
	return &roleSnapshot{byNS: byNS}
}

// Load reads every role from storage and publishes them. Called on the active
// node during unseal, after the namespaces and mounts are loaded.
func (s *RoleStore) Load(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.storage == nil {
		s.storage = NewBarrierView(s.core.barrier, roleStorePath)
	}
	snap, count, err := s.loadAllLocked(ctx)
	if err != nil {
		return err
	}
	s.snapshot.Store(snap)
	s.loaded = true
	s.logger.Debug("role store loaded", logger.Int("roles", count))
	return nil
}

// Unload drops the snapshot. The records stay in storage for the next Load.
func (s *RoleStore) Unload() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.snapshot.Store(emptyRoleSnapshot)
	s.loaded = false
}

// writableLocked reports why the store cannot take a write, or nil. Caller
// holds mu.
func (s *RoleStore) writableLocked() error {
	if !s.loaded || s.storage == nil {
		return ErrRoleStoreNotLoaded
	}
	return nil
}

// Get returns a copy of the role name in the namespace in ctx, and the hash a
// conditional write passes back.
func (s *RoleStore) Get(ctx context.Context, name string) (*logical.Role, string, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, "", ErrNamespaceNotInContext
	}
	e := s.snapshot.Load().lookup(ns.ID, name)
	if e == nil {
		return nil, "", ErrRoleNotFound
	}
	return e.role.Clone(), e.hash, nil
}

// List returns copies of every role in the namespace in ctx, sorted by name.
func (s *RoleStore) List(ctx context.Context) ([]*logical.Role, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, ErrNamespaceNotInContext
	}
	nr := s.snapshot.Load().byNS[ns.ID]
	if nr == nil {
		return nil, nil
	}
	out := make([]*logical.Role, 0, len(nr.byName))
	for _, e := range nr.byName {
		out = append(out, e.role.Clone())
	}
	slices.SortFunc(out, func(a, b *logical.Role) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

// Create stores a new role in the namespace in ctx. role is normalized in place
// and receives its timestamps; the store keeps its own copy. The returned
// warnings name policies and the credential spec that do not exist yet.
func (s *RoleStore) Create(ctx context.Context, role *logical.Role) ([]string, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, ErrNamespaceNotInContext
	}

	warnings, err := s.validateRole(ctx, role)
	if err != nil {
		return nil, err
	}

	err = func() error {
		s.mu.Lock()
		defer s.mu.Unlock()

		if err := s.writableLocked(); err != nil {
			return err
		}
		snap := s.snapshot.Load()
		if snap.lookup(ns.ID, role.Name) != nil {
			return ErrRoleAlreadyExists
		}

		now := time.Now().UTC()
		role.CreatedAt, role.UpdatedAt = now, now
		e := &roleEntry{role: role.Clone(), hash: role.Hash()}
		if err := s.persistRole(ctx, ns.UUID, e); err != nil {
			return err
		}
		s.snapshot.Store(snap.withEntry(ns.ID, role.Name, e))
		return nil
	}()
	if err != nil {
		return nil, err
	}

	s.logger.Info("created role",
		logger.String("namespace", ns.Path),
		logger.String("name", role.Name))
	return warnings, nil
}

// Update replaces a role in the namespace in ctx with role, keeping its
// creation time. When expectedHash is set the write is refused with
// ErrRoleChanged unless the stored role still has that hash: a caller that
// built role from an earlier read passes that read's hash. role is normalized in
// place and receives its timestamps.
func (s *RoleStore) Update(ctx context.Context, role *logical.Role, expectedHash string) ([]string, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, ErrNamespaceNotInContext
	}

	warnings, err := s.validateRole(ctx, role)
	if err != nil {
		return nil, err
	}
	if s.beforeUpdate != nil {
		s.beforeUpdate()
	}

	err = func() error {
		s.mu.Lock()
		defer s.mu.Unlock()

		if err := s.writableLocked(); err != nil {
			return err
		}
		snap := s.snapshot.Load()
		cur := snap.lookup(ns.ID, role.Name)
		if cur == nil {
			return ErrRoleNotFound
		}
		if expectedHash != "" && cur.hash != expectedHash {
			return ErrRoleChanged
		}

		role.CreatedAt, role.UpdatedAt = cur.role.CreatedAt, time.Now().UTC()
		e := &roleEntry{role: role.Clone(), hash: role.Hash()}
		if err := s.persistRole(ctx, ns.UUID, e); err != nil {
			return err
		}
		s.snapshot.Store(snap.withEntry(ns.ID, role.Name, e))
		return nil
	}()
	if err != nil {
		return nil, err
	}

	s.logger.Info("updated role",
		logger.String("namespace", ns.Path),
		logger.String("name", role.Name))
	return warnings, nil
}

// Delete removes a role from the namespace in ctx. expectedHash makes it
// conditional, as for Update.
func (s *RoleStore) Delete(ctx context.Context, name, expectedHash string) error {
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
		snap := s.snapshot.Load()
		cur := snap.lookup(ns.ID, name)
		if cur == nil {
			return ErrRoleNotFound
		}
		if expectedHash != "" && cur.hash != expectedHash {
			return ErrRoleChanged
		}
		if err := s.storage.Delete(ctx, roleStorageKey(ns.UUID, name)); err != nil {
			return fmt.Errorf("failed to delete role %q: %w", name, err)
		}
		s.snapshot.Store(snap.withEntry(ns.ID, name, nil))
		return nil
	}()
	if err != nil {
		return err
	}

	s.logger.Info("deleted role",
		logger.String("namespace", ns.Path),
		logger.String("name", name))
	return nil
}

// ClearNamespace deletes every role of the namespace in ctx, from storage and
// from the snapshot. Called during namespace deletion. It sweeps what storage
// holds, so a record the snapshot skipped at load is removed too.
func (s *RoleStore) ClearNamespace(ctx context.Context) error {
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

	names, err := s.storage.List(ctx, roleListPrefix(ns.UUID))
	if err != nil {
		return fmt.Errorf("failed to list roles for namespace cleanup: %w", err)
	}
	for _, name := range names {
		if err := s.storage.Delete(ctx, roleStorageKey(ns.UUID, name)); err != nil {
			return fmt.Errorf("failed to delete role %s during namespace cleanup: %w", name, err)
		}
	}
	snap := s.snapshot.Load()
	if snap.byNS[ns.ID] != nil {
		s.snapshot.Store(snap.withNamespace(ns.ID, nil))
	}

	if len(names) > 0 {
		s.logger.Info("cleared roles for namespace",
			logger.String("namespace", ns.UUID),
			logger.Int("roles_deleted", len(names)))
	}
	return nil
}

// validateRole normalizes role in place and checks it. It reads the policy
// store and the credential configs, so it runs before mu is taken. A policy or
// a credential spec that does not exist is a warning, not an error: either may
// be written after the role.
func (s *RoleStore) validateRole(ctx context.Context, role *logical.Role) ([]string, error) {
	if role == nil {
		return nil, logical.ErrBadRequest("role is required")
	}
	if !validSysName(role.Name) {
		return nil, logical.ErrBadRequestf("invalid role name %q: %s", role.Name, sysNameRule)
	}
	if role.CredSpecName != "" && !validSysName(role.CredSpecName) {
		return nil, logical.ErrBadRequestf("invalid cred_spec_name %q: %s", role.CredSpecName, sysNameRule)
	}

	policies, err := normalizeRolePolicies(role.Policies)
	if err != nil {
		return nil, err
	}
	if err := logical.ValidateAssignablePolicies(policies); err != nil {
		return nil, logical.ErrBadRequest(err.Error())
	}
	role.Policies = policies

	providerPath, err := authhelper.ValidateDiscoveryFields(role.Skill, role.ProviderPath)
	if err != nil {
		return nil, err
	}
	role.ProviderPath = providerPath

	if len(role.Description) > logical.MaxRoleDescriptionBytes {
		return nil, logical.ErrBadRequestf("description exceeds %d bytes", logical.MaxRoleDescriptionBytes)
	}
	if len(role.Metadata) > logical.MaxRoleMetadataKeys {
		return nil, logical.ErrBadRequestf("metadata has %d keys; at most %d are allowed",
			len(role.Metadata), logical.MaxRoleMetadataKeys)
	}
	for _, k := range slices.Sorted(maps.Keys(role.Metadata)) {
		switch {
		case k == "":
			return nil, logical.ErrBadRequest("metadata keys must not be empty")
		case len(k) > logical.MaxRoleMetadataKeyBytes:
			return nil, logical.ErrBadRequestf("metadata key starting %.32q exceeds %d bytes", k, logical.MaxRoleMetadataKeyBytes)
		case len(role.Metadata[k]) > logical.MaxRoleMetadataValueBytes:
			return nil, logical.ErrBadRequestf("metadata value of %q exceeds %d bytes", k, logical.MaxRoleMetadataValueBytes)
		}
	}
	if len(role.Metadata) == 0 {
		role.Metadata = nil
	}

	var warnings []string
	if s.core.policyStore != nil {
		for _, p := range role.Policies {
			if pol, err := s.core.policyStore.getPolicyAnyType(ctx, p); err == nil && pol == nil {
				warnings = append(warnings, fmt.Sprintf("policy %q does not exist yet", p))
			}
		}
	}
	if role.CredSpecName != "" && s.core.credentialManager != nil &&
		!s.core.credentialManager.SpecExists(ctx, role.CredSpecName) {
		warnings = append(warnings, fmt.Sprintf("credential spec %q does not exist yet", role.CredSpecName))
	}
	return warnings, nil
}

// normalizeRolePolicies returns policies trimmed and lower-cased (the form the
// policy store names them by), sorted and deduplicated. An empty name is
// refused.
func normalizeRolePolicies(policies []string) ([]string, error) {
	out := make([]string, 0, len(policies))
	for _, p := range policies {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			return nil, logical.ErrBadRequest("policy names must not be empty")
		}
		out = append(out, p)
	}
	slices.Sort(out)
	// Clipped, so no append through a published role's slice can reach past it.
	return slices.Clip(slices.Compact(out)), nil
}

// sysNameRegex is the rule for the name of a sys/ object, taken from the path
// pattern sys/roles/<name> and sys/cred/specs/<name> route on.
var sysNameRegex = regexp.MustCompile("^" + framework.GenericNameRegex("name") + "$")

// sysNameRule states sysNameRegex for error messages.
const sysNameRule = `letters, digits, "_", "-" and ".", starting and ending with a letter, digit or "_"`

// validSysName reports whether name can name a sys/ object (a role, a
// credential spec).
func validSysName(name string) bool {
	return sysNameRegex.MatchString(name)
}

// setupRoleStore wires the role store to the unsealed barrier and, on the
// active node, loads it. A standby loads nothing: it forwards every request,
// and it loads when it becomes active.
func (c *Core) setupRoleStore(ctx context.Context, standby bool) error {
	if c.roleStore == nil {
		return fmt.Errorf("role store not initialized")
	}
	if standby {
		return nil
	}
	return c.roleStore.Load(ctx)
}

// teardownRoleStore is the seal-time inverse of setupRoleStore.
func (c *Core) teardownRoleStore() {
	if c.roleStore != nil {
		c.roleStore.Unload()
	}
}
