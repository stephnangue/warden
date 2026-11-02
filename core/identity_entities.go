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

	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

var (
	ErrEntityNotFound      = errors.New("entity not found")
	ErrEntityAlreadyExists = errors.New("entity already exists")
	ErrTooManyEntities     = errors.New("too many entities in the namespace")
	ErrAliasNotFound       = errors.New("native identity not claimed")

	// ErrEntityChanged is returned by UpdateEntity and DeleteEntity when the
	// caller passed an expected hash and the stored entity no longer has it.
	ErrEntityChanged = errors.New("entity changed concurrently")

	// ErrEntityRetired refuses a write to a retired entity: retirement is
	// final, and the record is kept read-only for audit, with the native
	// identities it claimed, so they stay claimed. They can be moved to
	// another entity; the record is deleted only with force.
	ErrEntityRetired = errors.New("entity is retired: its record is read-only")

	// ErrSponsorNotFound refuses a write that acts on a sponsor or a pending
	// handover the entity does not have.
	ErrSponsorNotFound = errors.New("no such sponsor")

	// ErrSponsorGroupNotFound and ErrSponsorGroupNotVirtual refuse a sponsor
	// naming a group that does not exist (or was deleted and created again)
	// or whose members are not humans' facts.
	ErrSponsorGroupNotFound   = errors.New("sponsor group not found")
	ErrSponsorGroupNotVirtual = errors.New("sponsor group is not a virtual group")

	// ErrSponsorChanged refuses a write decided on a sponsor or a pending
	// handover the entity no longer has.
	ErrSponsorChanged = errors.New("sponsor changed concurrently")
)

// entityIDSegment is the path segment that reads an entity by ID
// (sys/identity/entity/id/<id>), so no entity can be named after it.
const entityIDSegment = "id"

// Storage layout, beside the groups under the identity store's barrier view:
//
//	{namespace-uuid}/entity/{id} -> JSON-encoded StoredEntity
//
// An entity is stored under its ID, so a rename rewrites one record.
const entityKeySegment = "entity/"

func entityListPrefix(nsUUID string) string { return nsUUID + "/" + entityKeySegment }

func entityStorageKey(nsUUID, id string) string { return entityListPrefix(nsUUID) + id }

const storedEntityVersion = 1

// StoredEntity is the storage record of one entity.
type StoredEntity struct {
	Version int             `json:"version"`
	Entity  *logical.Entity `json:"entity"`
	Hash    string          `json:"hash"`
}

// namespaceEntities returns the published entities of namespace nsID. Lock-free.
func (s *IdentityStore) namespaceEntities(nsID string) *nsEntities {
	return s.namespaceIndex(nsID).entities
}

// EntityByAlias returns the published entity that claims the native identity
// (accessor, name) in namespace nsID, or nil. It takes no lock and does not
// allocate. The entity is shared: callers must not modify it.
func (s *IdentityStore) EntityByAlias(nsID, accessor, name string) *logical.Entity {
	if accessor == "" || name == "" {
		return nil
	}
	if en := s.namespaceEntities(nsID).byAlias(accessor, name); en != nil {
		return en.Entity
	}
	return nil
}

// AliasesBoundTo reports how many native identities are claimed on the auth
// mount with accessor, across every namespace (an accessor belongs to one).
// It walks that accessor's keys in each namespace, not every entity.
func (s *IdentityStore) AliasesBoundTo(accessor string) int {
	n := 0
	for _, g := range s.snapshot.Load().byNS {
		n += g.entities.aliasesOn(accessor)
	}
	return n
}

// GetEntity returns a copy of the entity name in the namespace in ctx, with its
// hash.
func (s *IdentityStore) GetEntity(ctx context.Context, name string) (*logical.Entity, string, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, "", ErrNamespaceNotInContext
	}
	en := s.namespaceEntities(ns.ID).named(name)
	if en == nil {
		return nil, "", ErrEntityNotFound
	}
	return en.Clone(), en.hash, nil
}

// GetEntityByID returns a copy of the entity with id in the namespace in ctx,
// with its hash.
func (s *IdentityStore) GetEntityByID(ctx context.Context, id string) (*logical.Entity, string, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, "", ErrNamespaceNotInContext
	}
	en := s.namespaceEntities(ns.ID).get(id)
	if en == nil {
		return nil, "", ErrEntityNotFound
	}
	return en.Clone(), en.hash, nil
}

// LookupAlias returns a copy of the entity that claims the native identity
// (accessor, name) in the namespace in ctx.
func (s *IdentityStore) LookupAlias(ctx context.Context, accessor, name string) (*logical.Entity, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, ErrNamespaceNotInContext
	}
	en := s.namespaceEntities(ns.ID).byAlias(accessor, name)
	if en == nil {
		return nil, ErrAliasNotFound
	}
	return en.Clone(), nil
}

// SponsorState selects entities in a listing by their sponsor.
type SponsorState string

const (
	// SponsorStateAccepted selects the entities with a sponsor.
	SponsorStateAccepted SponsorState = "accepted"

	// SponsorStatePending selects the entities with a pending handover,
	// governed or not.
	SponsorStatePending SponsorState = "pending"
)

// EntityFilter selects entities in a listing; zero fields select everything.
type EntityFilter struct {
	Kind  string
	State logical.EntityState
	// Sponsor selects the entities whose sponsor is the group of that name,
	// in any namespace.
	Sponsor      string
	SponsorState SponsorState
	Ungoverned   bool
	GovernedBy   string
	// MountGone, when set, selects only entities claiming a native identity on
	// a mount it reports gone: orphaned claims, left by a forced disable.
	MountGone func(accessor string) bool
}

func (f EntityFilter) match(e *logical.Entity) bool {
	switch {
	case f.Kind != "" && e.Kind != f.Kind,
		f.State != "" && e.State != f.State,
		f.Sponsor != "" && (e.Sponsor == nil || e.Sponsor.Group != f.Sponsor),
		f.SponsorState == SponsorStateAccepted && e.Sponsor == nil,
		f.SponsorState == SponsorStatePending && e.PendingSponsor == nil,
		f.Ungoverned && e.GovernedBy() != "",
		f.GovernedBy != "" && e.GovernedBy() != f.GovernedBy,
		f.MountGone != nil && !slices.ContainsFunc(e.Aliases, func(a logical.EntityAlias) bool {
			return f.MountGone(a.MountAccessor)
		}):
		return false
	}
	return true
}

// ListEntities returns copies of the entities of the namespace in ctx that f
// selects, sorted by name, with their hashes.
func (s *IdentityStore) ListEntities(ctx context.Context, f EntityFilter) ([]*logical.Entity, []string, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, nil, ErrNamespaceNotInContext
	}
	var out []*logical.Entity
	var hashes []string
	s.namespaceEntities(ns.ID).all(func(en *entityEntry) bool {
		if f.match(en.Entity) {
			out = append(out, en.Clone())
			hashes = append(hashes, en.hash)
		}
		return true
	})
	return out, hashes, nil
}

// CreateEntity stores a new entity in the namespace in ctx: e carries its
// name, kind and governance fields, and the native identities it claims, each
// naming its mount by accessor. An entity is created without a sponsor: one is
// proposed afterwards (ProposeSponsor). e is normalized in place and receives
// its ID and timestamps; the store keeps its own copy.
func (s *IdentityStore) CreateEntity(ctx context.Context, e *logical.Entity) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return ErrNamespaceNotInContext
	}
	if err := validateEntity(e); err != nil {
		return err
	}
	if e.Sponsor != nil || e.PendingSponsor != nil {
		return logical.ErrBadRequest("an entity is created without a sponsor; propose one afterwards")
	}
	if e.Kind == "" {
		e.Kind = logical.EntityKindAgent
	}
	if e.State == "" {
		e.State = logical.EntityStateActive
	}
	id, err := uuid.GenerateUUID()
	if err != nil {
		return fmt.Errorf("failed to generate entity id: %w", err)
	}
	now := time.Now().UTC()
	e.ID, e.CreatedAt, e.UpdatedAt = id, now, now
	for i := range e.Aliases {
		e.Aliases[i].CreatedAt = now
	}

	err = func() error {
		s.mu.Lock()
		defer s.mu.Unlock()

		if err := s.writableLocked(); err != nil {
			return err
		}
		cur := s.namespaceEntities(ns.ID)
		if cur.named(e.Name) != nil {
			return ErrEntityAlreadyExists
		}
		if max := logical.MaxEntitiesPerNamespace; cur.count() >= max {
			return fmt.Errorf("%w: the namespace has %d/%d entities", ErrTooManyEntities, cur.count(), max)
		}
		stored := newEntityEntry(e.Clone())
		next, err := cur.with(entityChange{next: stored})
		if err != nil {
			return err
		}
		if err := s.persistEntity(ctx, ns.UUID, stored); err != nil {
			return err
		}
		s.publishEntitiesLocked(ns.ID, next)
		return nil
	}()
	if err != nil {
		return err
	}
	s.logger.Info("created entity",
		logger.String("namespace", ns.Path),
		logger.String("name", e.Name),
		logger.Int("aliases", len(e.Aliases)))
	return nil
}

// UpdateEntity replaces the descriptive fields of the entity name in the
// namespace in ctx with next's: its name (a rename), description, profile and
// metadata. The kind never changes; the aliases change only through
// ClaimAlias and RemoveAlias, the sponsor and the pending handover through the
// sponsor methods, the state through SetEntityState; a retired entity refuses
// every update. When expectedHash is set the write applies only if the stored
// entity still has that hash. next is normalized in place and receives the
// stored ID, aliases, sponsors, state and creation time.
func (s *IdentityStore) UpdateEntity(ctx context.Context, name string, next *logical.Entity, expectedHash string) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return ErrNamespaceNotInContext
	}
	if err := validateEntity(next); err != nil {
		return err
	}

	err = func() error {
		s.mu.Lock()
		defer s.mu.Unlock()

		if err := s.writableLocked(); err != nil {
			return err
		}
		cur := s.namespaceEntities(ns.ID)
		old := cur.named(name)
		if old == nil {
			return ErrEntityNotFound
		}
		if expectedHash != "" && old.hash != expectedHash {
			return ErrEntityChanged
		}
		if old.State == logical.EntityStateRetired {
			return ErrEntityRetired
		}
		if next.Kind != "" && next.Kind != old.Kind {
			return logical.ErrBadRequestf("kind cannot change: entity %q is %s", name, old.Kind)
		}
		next.ID, next.Kind, next.CreatedAt, next.UpdatedAt = old.ID, old.Kind, old.CreatedAt, time.Now().UTC()
		next.Aliases = slices.Clone(old.Aliases)
		next.Sponsor, next.PendingSponsor, next.State = old.Sponsor, old.PendingSponsor, old.State
		stored := newEntityEntry(next.Clone())
		ents, err := cur.with(entityChange{old: old, next: stored})
		if err != nil {
			return err
		}
		if err := s.persistEntity(ctx, ns.UUID, stored); err != nil {
			return err
		}
		s.publishEntitiesLocked(ns.ID, ents)
		return nil
	}()
	if err != nil {
		return err
	}
	s.logger.Info("updated entity",
		logger.String("namespace", ns.Path),
		logger.String("name", next.Name))
	return nil
}

// DeleteEntity removes the entity name from the namespace in ctx, releasing
// the native identities it claimed. expectedHash makes it conditional. A
// retired entity is deleted only with force, which is logged and returns a
// warning for the delete's response: its native identities are unclaimed
// again.
func (s *IdentityStore) DeleteEntity(ctx context.Context, name, expectedHash string, force bool) (warning string, err error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return "", ErrNamespaceNotInContext
	}

	err = func() error {
		s.mu.Lock()
		defer s.mu.Unlock()

		if err := s.writableLocked(); err != nil {
			return err
		}
		cur := s.namespaceEntities(ns.ID)
		old := cur.named(name)
		if old == nil {
			return ErrEntityNotFound
		}
		if expectedHash != "" && old.hash != expectedHash {
			return ErrEntityChanged
		}
		if old.State == logical.EntityStateRetired {
			if !force {
				return ErrEntityRetired
			}
			s.logger.Warn("deleting a retired entity (force): its native identities are unclaimed again",
				logger.String("namespace", ns.Path),
				logger.String("name", name),
				logger.Int("aliases", len(old.Aliases)))
			warning = fmt.Sprintf("forced: retired entity %q deleted; the %d native identities it claimed are unclaimed again",
				name, len(old.Aliases))
		}
		ents, err := cur.with(entityChange{old: old})
		if err != nil {
			return err
		}
		if err := s.storage.Delete(ctx, entityStorageKey(ns.UUID, old.ID)); err != nil {
			return fmt.Errorf("failed to delete entity %q: %w", name, err)
		}
		s.publishEntitiesLocked(ns.ID, ents)
		return nil
	}()
	if err != nil {
		return "", err
	}
	s.logger.Info("deleted entity",
		logger.String("namespace", ns.Path),
		logger.String("name", name))
	return warning, nil
}

// ClaimAlias adds the native identity (accessor, alias) to the entity name in
// the namespace in ctx. A native identity another entity claims is refused,
// unless move is set or that entity is retired: then it is taken from it. The
// loser is written first, so a crash between the two writes leaves the native
// identity unclaimed, never claimed twice. It returns the entity it was taken
// from, or "". Claiming one the entity already claims changes nothing.
func (s *IdentityStore) ClaimAlias(ctx context.Context, name, accessor, alias string, move bool) (string, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return "", ErrNamespaceNotInContext
	}
	if !validAccessor(accessor) {
		return "", logical.ErrBadRequest("every native identity names its mount")
	}
	if !logical.ValidAliasName(alias) {
		return "", logical.ErrBadRequestf("invalid native identity %.64q: at most %d bytes of printable text",
			alias, logical.MaxAliasNameBytes)
	}
	var from string
	err = func() error {
		s.mu.Lock()
		defer s.mu.Unlock()

		if err := s.writableLocked(); err != nil {
			return err
		}
		cur := s.namespaceEntities(ns.ID)
		winner := cur.named(name)
		if winner == nil {
			return ErrEntityNotFound
		}
		if winner.State == logical.EntityStateRetired {
			return ErrEntityRetired
		}
		holder := cur.byAlias(accessor, alias)
		if holder != nil && holder.ID == winner.ID {
			return nil
		}
		if len(winner.Aliases) >= logical.MaxEntityAliases {
			return logical.ErrBadRequestf("entity %q already claims %d/%d native identities",
				name, len(winner.Aliases), logical.MaxEntityAliases)
		}
		now := time.Now().UTC()
		var changes []entityChange
		if holder != nil {
			if !move && holder.State != logical.EntityStateRetired {
				return &entityConflictError{accessor: accessor, alias: alias, entity: holder.Name, move: true}
			}
			loser := holder.Clone()
			loser.Aliases = slices.DeleteFunc(loser.Aliases, func(a logical.EntityAlias) bool {
				return a.MountAccessor == accessor && a.Name == alias
			})
			loser.UpdatedAt = now
			changes = append(changes, entityChange{old: holder, next: newEntityEntry(loser)})
			from = holder.Name
		}
		gainer := winner.Clone()
		gainer.Aliases = append(gainer.Aliases, logical.EntityAlias{MountAccessor: accessor, Name: alias, CreatedAt: now})
		logical.SortAliases(gainer.Aliases)
		gainer.UpdatedAt = now
		changes = append(changes, entityChange{old: winner, next: newEntityEntry(gainer)})

		ents, err := cur.with(changes...)
		if err != nil {
			return err
		}
		for i, c := range changes {
			if err := s.persistEntity(ctx, ns.UUID, c.next); err != nil {
				// The loser is stored without the native identity and the
				// winner is not stored with it: publish what storage holds,
				// the identity unclaimed, so a reload changes nothing.
				if i > 0 {
					if stored, werr := cur.with(changes[:i]...); werr == nil {
						s.publishEntitiesLocked(ns.ID, stored)
					}
				}
				return err
			}
		}
		s.publishEntitiesLocked(ns.ID, ents)
		return nil
	}()
	if err != nil {
		return "", err
	}
	s.logger.Info("claimed native identity",
		logger.String("namespace", ns.Path),
		logger.String("entity", name),
		logger.String("mount_accessor", accessor),
		logger.String("moved_from", from))
	return from, nil
}

// RemoveAlias releases the native identity (accessor, alias) from the entity
// name in the namespace in ctx. A retired entity keeps its native identities:
// they can be moved to another entity (ClaimAlias), never released.
func (s *IdentityStore) RemoveAlias(ctx context.Context, name, accessor, alias string) error {
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
		cur := s.namespaceEntities(ns.ID)
		old := cur.named(name)
		if old == nil {
			return ErrEntityNotFound
		}
		i := old.FindAlias(accessor, alias)
		if i < 0 {
			return ErrAliasNotFound
		}
		if old.State == logical.EntityStateRetired {
			return ErrEntityRetired
		}
		next := old.Clone()
		next.Aliases = slices.Delete(next.Aliases, i, i+1)
		next.UpdatedAt = time.Now().UTC()
		stored := newEntityEntry(next)
		ents, err := cur.with(entityChange{old: old, next: stored})
		if err != nil {
			return err
		}
		if err := s.persistEntity(ctx, ns.UUID, stored); err != nil {
			return err
		}
		s.publishEntitiesLocked(ns.ID, ents)
		return nil
	}()
	if err != nil {
		return err
	}
	s.logger.Info("released native identity",
		logger.String("namespace", ns.Path),
		logger.String("entity", name),
		logger.String("mount_accessor", accessor))
	return nil
}

// ProposeOutcome is what ProposeSponsor did.
type ProposeOutcome int

const (
	// ProposeUnchanged: the group already sponsors the entity.
	ProposeUnchanged ProposeOutcome = iota

	// ProposeAccepted: the group is the sponsor now, accepted by its
	// proposer, a member of it. It replaced any earlier sponsor in the same
	// write.
	ProposeAccepted

	// ProposePending: the group is the pending handover now, replacing any
	// earlier one; the sponsor, if any, is unchanged.
	ProposePending
)

// ProposeSponsor proposes the group sp names as the sponsor of the entity name
// in the namespace in ctx. accepted says its proposer is a member of the
// group, decided by the caller: sp becomes the sponsor at once, accepted by
// its proposer (a pending handover to the same group is consumed, any other
// stays). Otherwise sp becomes the pending handover. Proposing the sponsor
// changes nothing.
//
// The group is checked again under the lock: it must still exist with sp's ID
// and be virtual, so a concurrent delete never leaves an entry naming a group
// that is gone. A non-nil expectSponsor refuses the write, with
// ErrSponsorChanged, unless the entity's sponsor is still that group: the
// caller decided it on a read that a concurrent write may have overtaken.
func (s *IdentityStore) ProposeSponsor(ctx context.Context, name string, sp *logical.EntitySponsor, accepted bool,
	expectSponsor *logical.EntitySponsor, expectedHash string) (ProposeOutcome, error) {
	if sp == nil {
		return 0, logical.ErrBadRequest("sponsor is required")
	}
	entry := *sp
	if accepted {
		entry.AcceptedBy, entry.AcceptedAt = entry.AddedBy, entry.AddedAt
	}
	if err := validateSponsor(&entry, accepted); err != nil {
		return 0, err
	}
	outcome := ProposeUnchanged
	err := s.writeEntity(ctx, name, expectedHash, "proposed a sponsor", func(old *entityEntry, next *logical.Entity) (bool, error) {
		if err := s.sponsorGroupLocked(&entry); err != nil {
			return false, err
		}
		if expectSponsor != nil && !old.Sponsor.Same(expectSponsor) {
			return false, ErrSponsorChanged
		}
		if entry.Same(old.Sponsor) {
			return false, nil
		}
		if accepted {
			next.Sponsor = &entry
			if entry.Same(next.PendingSponsor) {
				next.PendingSponsor = nil
			}
			outcome = ProposeAccepted
		} else {
			next.PendingSponsor = &entry
			outcome = ProposePending
		}
		return true, nil
	})
	if err != nil {
		return 0, err
	}
	return outcome, nil
}

// CancelPending withdraws the pending handover of the entity name;
// ErrSponsorNotFound when none is pending. A non-nil expect refuses the write
// unless the pending handover is still that group (ErrSponsorChanged).
func (s *IdentityStore) CancelPending(ctx context.Context, name string, expect *logical.EntitySponsor, expectedHash string) error {
	return s.writeEntity(ctx, name, expectedHash, "cancelled a sponsor handover", func(old *entityEntry, next *logical.Entity) (bool, error) {
		switch {
		case old.PendingSponsor == nil:
			return false, ErrSponsorNotFound
		case expect != nil && !old.PendingSponsor.Same(expect):
			return false, ErrSponsorChanged
		}
		next.PendingSponsor = nil
		return true, nil
	})
}

// ClearSponsor removes the sponsor of the entity name, which is ungoverned
// after it; ErrSponsorNotFound when it has none. A pending handover stays.
func (s *IdentityStore) ClearSponsor(ctx context.Context, name, expectedHash string) error {
	return s.writeEntity(ctx, name, expectedHash, "removed a sponsor", func(old *entityEntry, next *logical.Entity) (bool, error) {
		if old.Sponsor == nil {
			return false, ErrSponsorNotFound
		}
		next.Sponsor = nil
		return true, nil
	})
}

// SetEntityState moves the entity name to state st; retired is final, so a
// retired entity refuses it. A non-nil expectSponsor refuses the write unless
// the entity's sponsor is still that group (ErrSponsorChanged): the caller was
// allowed the change as a member of it.
func (s *IdentityStore) SetEntityState(ctx context.Context, name string, st logical.EntityState,
	expectSponsor *logical.EntitySponsor, expectedHash string) error {
	if _, err := logical.ParseEntityState(string(st)); err != nil || st == "" {
		return logical.ErrBadRequest("state must be active, suspended or retired")
	}
	return s.writeEntity(ctx, name, expectedHash, "changed entity state", func(old *entityEntry, next *logical.Entity) (bool, error) {
		if expectSponsor != nil && !old.Sponsor.Same(expectSponsor) {
			return false, ErrSponsorChanged
		}
		if old.State == st {
			return false, nil
		}
		next.State = st
		return true, nil
	})
}

// sponsorGroupLocked checks that the group sp names exists, with sp's ID, and
// is virtual. Caller holds mu.
func (s *IdentityStore) sponsorGroupLocked(sp *logical.EntitySponsor) error {
	g := s.namespaceIndex(sp.Namespace).groupsByName[sp.Group]
	switch {
	case g == nil || g.ID != sp.GroupID:
		return ErrSponsorGroupNotFound
	case g.Type != logical.GroupTypeVirtual:
		return ErrSponsorGroupNotVirtual
	}
	return nil
}

// writeEntity applies change to a copy of the entity name in the namespace in
// ctx and publishes it, when change reports a change, with one storage write.
// A missing entity, an expectedHash it no longer has and a retired entity are
// refused before change runs. change runs under mu; it reads old and writes
// next.
func (s *IdentityStore) writeEntity(ctx context.Context, name, expectedHash, what string,
	change func(old *entityEntry, next *logical.Entity) (bool, error)) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return ErrNamespaceNotInContext
	}
	changed := false
	err = func() error {
		s.mu.Lock()
		defer s.mu.Unlock()

		if err := s.writableLocked(); err != nil {
			return err
		}
		cur := s.namespaceEntities(ns.ID)
		old := cur.named(name)
		if old == nil {
			return ErrEntityNotFound
		}
		if expectedHash != "" && old.hash != expectedHash {
			return ErrEntityChanged
		}
		if old.State == logical.EntityStateRetired {
			return ErrEntityRetired
		}
		next := old.Clone()
		if changed, err = change(old, next); err != nil || !changed {
			return err
		}
		next.UpdatedAt = time.Now().UTC()
		if err := validateEntity(next); err != nil {
			return err
		}
		stored := newEntityEntry(next)
		ents, err := cur.with(entityChange{old: old, next: stored})
		if err != nil {
			return err
		}
		if err := s.persistEntity(ctx, ns.UUID, stored); err != nil {
			return err
		}
		s.publishEntitiesLocked(ns.ID, ents)
		return nil
	}()
	if err != nil || !changed {
		return err
	}
	s.logger.Info(what,
		logger.String("namespace", ns.Path),
		logger.String("entity", name))
	return nil
}

// publishEntitiesLocked makes ents the namespace's entities under the next
// generation, keeping its groups as published. Caller holds mu.
func (s *IdentityStore) publishEntitiesLocked(nsID string, ents *nsEntities) {
	snap := s.snapshot.Load()
	cur := snap.namespace(nsID)
	var next *nsIndex
	if len(cur.groupsByName) > 0 || ents.count() > 0 {
		n := *cur
		n.gen = s.gen.Add(1)
		n.entities = ents
		next = &n
	}
	s.snapshot.Store(snap.withNamespace(nsID, next))
}

// persistEntity writes en to storage. Caller holds mu.
func (s *IdentityStore) persistEntity(ctx context.Context, nsUUID string, en *entityEntry) error {
	e := en.Entity
	data, err := json.Marshal(&StoredEntity{Version: storedEntityVersion, Entity: e, Hash: en.hash})
	if err != nil {
		return fmt.Errorf("failed to marshal entity: %w", err)
	}
	if err := s.storage.Put(ctx, &sdklogical.StorageEntry{Key: entityStorageKey(nsUUID, e.ID), Value: data}); err != nil {
		return fmt.Errorf("failed to write entity %q: %w", e.Name, err)
	}
	return nil
}

// loadEntitiesLocked reads the stored entities of a namespace. A record that
// does not decode or validate, or whose name or native identity another
// record already holds, is logged and skipped. Caller holds mu.
func (s *IdentityStore) loadEntitiesLocked(ctx context.Context, ns *namespace.Namespace) (*nsEntities, error) {
	ids, err := s.storage.List(ctx, entityListPrefix(ns.UUID))
	if err != nil {
		return nil, fmt.Errorf("failed to list entities of namespace %q: %w", ns.Path, err)
	}
	skip := func(id string, err error) {
		s.logger.Warn("skipping a stored entity that cannot be loaded",
			logger.String("namespace", ns.Path),
			logger.String("id", id),
			logger.Err(err))
	}
	records := make([]*entityEntry, 0, len(ids))
	for _, id := range ids {
		e, err := s.readEntity(ctx, ns.UUID, id)
		if err != nil {
			skip(id, err)
			continue
		}
		records = append(records, newEntityEntry(e))
	}
	return loadEntities(records, func(en *entityEntry, err error) { skip(en.ID, err) }), nil
}

// readEntity reads and decodes one stored entity.
func (s *IdentityStore) readEntity(ctx context.Context, nsUUID, id string) (*logical.Entity, error) {
	entry, err := s.storage.Get(ctx, entityStorageKey(nsUUID, id))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, ErrEntityNotFound
	}
	var stored StoredEntity
	if err := json.Unmarshal(entry.Value, &stored); err != nil {
		return nil, fmt.Errorf("failed to decode: %w", err)
	}
	if stored.Version != storedEntityVersion {
		return nil, fmt.Errorf("unknown storage version %d", stored.Version)
	}
	if stored.Entity == nil || stored.Entity.ID != id {
		return nil, fmt.Errorf("record does not hold entity %q", id)
	}
	// stored.Hash is kept for whoever inspects storage and is not checked:
	// the published hash is recomputed, so a field Entity.Hash comes to cover
	// never invalidates a record written before it.
	if err := validateEntity(stored.Entity); err != nil {
		return nil, err
	}
	// Published as a clone, with no spare capacity left by the decoder.
	return stored.Entity.Clone(), nil
}

// clearEntitiesLocked deletes every stored entity of the namespace. Caller
// holds mu.
func (s *IdentityStore) clearEntitiesLocked(ctx context.Context, nsUUID string) (int, error) {
	ids, err := s.storage.List(ctx, entityListPrefix(nsUUID))
	if err != nil {
		return 0, fmt.Errorf("failed to list entities for namespace cleanup: %w", err)
	}
	for _, id := range ids {
		if err := s.storage.Delete(ctx, entityStorageKey(nsUUID, id)); err != nil {
			return 0, fmt.Errorf("failed to delete entity %s during namespace cleanup: %w", id, err)
		}
	}
	return len(ids), nil
}

// validAccessor reports whether accessor can name a native identity's mount:
// non-empty, at most maxAccessorBytes, and without NUL, which separates it
// from the alias name in the index key.
func validAccessor(accessor string) bool {
	return accessor != "" && len(accessor) <= maxAccessorBytes && !strings.ContainsRune(accessor, 0)
}

// validateSponsor checks one sponsor entry: accepted says which slot holds it,
// the sponsor (accepted by a member) or the pending handover (not yet).
func validateSponsor(sp *logical.EntitySponsor, accepted bool) error {
	switch {
	case sp.Type != logical.SponsorTypeGroup:
		return logical.ErrBadRequestf("unknown sponsor type %q: %q", sp.Type, logical.SponsorTypeGroup)
	case sp.Namespace == "" || sp.GroupID == "" || !validSysName(sp.Group):
		return logical.ErrBadRequest("a sponsor names its group by namespace, ID and name")
	case sp.AddedAt.IsZero() || sp.AddedBy.Principal == "":
		return logical.ErrBadRequest("a sponsor records who proposed it and when")
	case accepted && (sp.AcceptedAt.Before(sp.AddedAt) || sp.AcceptedBy.Principal == ""):
		return logical.ErrBadRequest("a sponsor records who accepted it and when, after it was proposed")
	case !accepted && (!sp.AcceptedAt.IsZero() || sp.AcceptedBy != logical.SponsorActor{}):
		return logical.ErrBadRequest("a pending handover is not accepted yet")
	}
	return nil
}

// validateEntity checks what a write may set, normalizing in place: aliases
// sorted. Unset kind and state are left for the caller to default.
func validateEntity(e *logical.Entity) error {
	if e == nil {
		return logical.ErrBadRequest("entity is required")
	}
	if !validSysName(e.Name) {
		return logical.ErrBadRequestf("invalid entity name %q: %s", e.Name, sysNameRule)
	}
	if e.Name == entityIDSegment {
		return logical.ErrBadRequestf("the entity name %q is reserved: sys/identity/entity/id/<id> reads an entity by ID",
			entityIDSegment)
	}
	switch e.Kind {
	case "", logical.EntityKindAgent:
	case logical.EntityKindHuman:
		return logical.ErrBadRequest(`kind "human" is not supported yet; only "agent" entities can be created`)
	default:
		return logical.ErrBadRequestf("unknown entity kind %q: %q", e.Kind, logical.EntityKindAgent)
	}
	if _, err := logical.ParseEntityState(string(e.State)); err != nil {
		return logical.ErrBadRequest(err.Error())
	}
	if len(e.Description) > logical.MaxEntityDescriptionBytes {
		return logical.ErrBadRequestf("description exceeds %d bytes", logical.MaxEntityDescriptionBytes)
	}
	if e.Sponsor != nil {
		if err := validateSponsor(e.Sponsor, true); err != nil {
			return err
		}
	}
	if e.PendingSponsor != nil {
		if err := validateSponsor(e.PendingSponsor, false); err != nil {
			return err
		}
		if e.PendingSponsor.Same(e.Sponsor) {
			return logical.ErrBadRequest("a pending handover names another group than the sponsor")
		}
	}
	if p := e.Profile; p != nil {
		for _, v := range []string{p.Purpose, p.Runtime, p.Publisher} {
			if len(v) > logical.MaxEntityProfileBytes {
				return logical.ErrBadRequestf("profile fields are at most %d bytes", logical.MaxEntityProfileBytes)
			}
		}
		if *p == (logical.AgentProfile{}) {
			e.Profile = nil
		}
	}
	if err := validateObjectMetadata(e.Metadata); err != nil {
		return err
	}
	if len(e.Metadata) == 0 {
		e.Metadata = nil
	} else {
		e.Metadata = maps.Clone(e.Metadata)
	}
	if len(e.Aliases) > logical.MaxEntityAliases {
		return logical.ErrBadRequestf("at most %d native identities per entity", logical.MaxEntityAliases)
	}
	for _, a := range e.Aliases {
		if !validAccessor(a.MountAccessor) {
			return logical.ErrBadRequest("every native identity names its mount")
		}
		if !logical.ValidAliasName(a.Name) {
			return logical.ErrBadRequestf("invalid native identity %.64q: at most %d bytes of printable text",
				a.Name, logical.MaxAliasNameBytes)
		}
	}
	logical.SortAliases(e.Aliases)
	for i := 1; i < len(e.Aliases); i++ {
		if e.Aliases[i].MountAccessor == e.Aliases[i-1].MountAccessor && e.Aliases[i].Name == e.Aliases[i-1].Name {
			return logical.ErrBadRequestf("native identity %q on mount %s is listed twice",
				e.Aliases[i].Name, e.Aliases[i].MountAccessor)
		}
	}
	return nil
}
