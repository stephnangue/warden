package core

import (
	"fmt"

	"github.com/cilium/statedb/part"

	"github.com/stephnangue/warden/logical"
)

// entityEntry is a published entity and its hash, computed once when it is
// published, so reads never hash. Immutable. Its Hash method recomputes:
// readers use hash.
type entityEntry struct {
	*logical.Entity
	hash string
}

// newEntityEntry wraps e, which the entry takes ownership of, for publishing.
func newEntityEntry(e *logical.Entity) *entityEntry {
	return &entityEntry{Entity: e, hash: e.Hash()}
}

// nsEntities is one namespace's entities, indexed three ways in persistent
// radix trees that share the same immutable entries: by ID, by name, and by
// native identity (mount accessor and alias name). Immutable once published:
// a write builds a new value with one transaction per tree, which copies only
// the paths it changes, and publishes it whole.
//
// Every use of the part package stays in this file, so that replacing it
// touches nothing else.
type nsEntities struct {
	byID    part.Tree[*entityEntry]
	byName  part.Tree[*entityEntry]
	aliases part.Tree[*entityEntry] // appendAliasKey(accessor, name)
}

// emptyEntities is the entities of a namespace with none. Its trees are never
// written: a write starts a transaction, which copies what it changes.
var emptyEntities = newEntities()

func newEntities() *nsEntities {
	return &nsEntities{
		byID:    part.New[*entityEntry](part.RootOnlyWatch),
		byName:  part.New[*entityEntry](part.RootOnlyWatch),
		aliases: part.New[*entityEntry](part.RootOnlyWatch),
	}
}

// count returns the number of entities.
func (e *nsEntities) count() int { return e.byID.Len() }

// aliasCount returns the number of native identities claimed.
func (e *nsEntities) aliasCount() int { return e.aliases.Len() }

// maxAccessorBytes bounds the mount accessor of a stored native identity.
const maxAccessorBytes = 128

// maxAliasKeyBytes covers an accessor, the separator and the longest alias,
// so a lookup builds its key on the stack.
const maxAliasKeyBytes = maxAccessorBytes + 1 + logical.MaxAliasNameBytes

// appendAliasKey appends the key of the native identity (accessor, name):
// the accessor, a NUL (which neither contains), and the name.
func appendAliasKey(dst []byte, accessor, name string) []byte {
	dst = append(dst, accessor...)
	dst = append(dst, 0)
	return append(dst, name...)
}

// byAlias returns the entry that claims the native identity (accessor, name),
// or nil. It takes no lock and, for any key that fits maxAliasKeyBytes, does
// not allocate.
func (e *nsEntities) byAlias(accessor, name string) *entityEntry {
	var buf [maxAliasKeyBytes]byte
	ent, _ := e.aliases.Get(appendAliasKey(buf[:0], accessor, name))
	return ent
}

// aliasesOn returns how many native identities are claimed on the mount with
// accessor: a walk of that accessor's keys only.
func (e *nsEntities) aliasesOn(accessor string) int {
	var buf [maxAccessorBytes + 1]byte
	n := 0
	e.aliases.Prefix(appendAliasKey(buf[:0], accessor, "")).All(func([]byte, *entityEntry) bool {
		n++
		return true
	})
	return n
}

// get returns the entry with id, or nil.
func (e *nsEntities) get(id string) *entityEntry {
	ent, _ := e.byID.Get([]byte(id))
	return ent
}

// named returns the entry called name, or nil.
func (e *nsEntities) named(name string) *entityEntry {
	ent, _ := e.byName.Get([]byte(name))
	return ent
}

// all calls yield with every entry in name order, until it returns false.
func (e *nsEntities) all(yield func(*entityEntry) bool) {
	e.byName.All(func(_ []byte, ent *entityEntry) bool { return yield(ent) })
}

// entityChange replaces old with next: old nil creates next, next nil deletes
// old. Both are published entries, never modified.
type entityChange struct {
	old, next *entityEntry
}

// entityConflictError is a write refused because a name or a native identity
// is held by another entity. It names the mount by accessor; a caller that can
// resolve mounts renders it by path (message).
type entityConflictError struct {
	// name is the entity name taken, for a name conflict; empty for a native
	// identity, which accessor and alias name and entity holds.
	name            string
	accessor, alias string
	entity          string
	// move says the write could take it with move.
	move bool
}

func (e *entityConflictError) Error() string {
	return e.message(func(accessor string) string { return accessor })
}

// message renders e, naming the mount through mount.
func (e *entityConflictError) message(mount func(accessor string) string) string {
	if e.name != "" {
		return fmt.Sprintf("entity %q already exists", e.name)
	}
	msg := fmt.Sprintf("native identity %q on mount %s is already claimed by entity %q", e.alias, mount(e.accessor), e.entity)
	if e.move {
		msg += "; pass move to take it"
	}
	return msg
}

// entityTxn is one write to an nsEntities: one transaction per tree.
type entityTxn struct {
	ids, names, aliases *part.Txn[*entityEntry]
}

func (e *nsEntities) txn() *entityTxn {
	return &entityTxn{ids: e.byID.Txn(), names: e.byName.Txn(), aliases: e.aliases.Txn()}
}

func (t *entityTxn) commit() *nsEntities {
	return &nsEntities{
		byID:    t.ids.CommitAndNotify(),
		byName:  t.names.CommitAndNotify(),
		aliases: t.aliases.CommitAndNotify(),
	}
}

// remove deletes every key of en.
func (t *entityTxn) remove(en *entityEntry) {
	var key [maxAliasKeyBytes]byte
	t.ids.Delete([]byte(en.ID))
	t.names.Delete([]byte(en.Name))
	for _, a := range en.Aliases {
		t.aliases.Delete(appendAliasKey(key[:0], a.MountAccessor, a.Name))
	}
}

// conflict returns why en cannot be inserted: its ID, name or a native
// identity is held by another entry. Nothing is written.
func (t *entityTxn) conflict(en *entityEntry) error {
	if prev, taken := t.ids.Get([]byte(en.ID)); taken && prev != en {
		return fmt.Errorf("entity id %q is held twice", en.ID)
	}
	if prev, taken := t.names.Get([]byte(en.Name)); taken && prev.ID != en.ID {
		return &entityConflictError{name: en.Name}
	}
	var key [maxAliasKeyBytes]byte
	for _, a := range en.Aliases {
		if prev, taken := t.aliases.Get(appendAliasKey(key[:0], a.MountAccessor, a.Name)); taken && prev.ID != en.ID {
			return &entityConflictError{accessor: a.MountAccessor, alias: a.Name, entity: prev.Name}
		}
	}
	return nil
}

// insert writes every key of en, which conflict has cleared.
func (t *entityTxn) insert(en *entityEntry) {
	t.ids.Insert([]byte(en.ID), en)
	t.names.Insert([]byte(en.Name), en)
	for _, a := range en.Aliases {
		// A fresh key: the tree keeps the slice it is given, so a reused
		// buffer must never be inserted.
		t.aliases.Insert(appendAliasKey(nil, a.MountAccessor, a.Name), en)
	}
}

// with returns e with changes applied, all or nothing: every key of every old
// entry is removed, then every key of every next entry inserted, so changes
// that hand a name or a native identity from one entity to another (a rename,
// an alias move) apply in one publish. A next entry whose name or alias
// another entity still holds refuses the whole write and e is left as it was.
// Caller holds the store's mu: a tree takes one transaction at a time.
func (e *nsEntities) with(changes ...entityChange) (*nsEntities, error) {
	t := e.txn()
	for _, c := range changes {
		if c.old != nil {
			t.remove(c.old)
		}
	}
	for _, c := range changes {
		if c.next == nil {
			continue
		}
		if err := t.conflict(c.next); err != nil {
			return nil, err
		}
		t.insert(c.next)
	}
	return t.commit(), nil
}

// loadEntities builds a namespace's entities from its stored records in one
// transaction per tree. A record that conflicts with one inserted before it
// (its ID, name or a native identity) is passed to skipped and left out
// whole. Caller holds the store's mu.
func loadEntities(records []*entityEntry, skipped func(*entityEntry, error)) *nsEntities {
	if len(records) == 0 {
		return emptyEntities
	}
	t := emptyEntities.txn()
	for _, en := range records {
		if err := t.conflict(en); err != nil {
			skipped(en, err)
			continue
		}
		t.insert(en)
	}
	return t.commit()
}
