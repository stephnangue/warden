package logical

import (
	"sync/atomic"
	"time"

	"github.com/stephnangue/warden/helper/selector"
)

// Entity kinds a mount admits, answered as the built-in fact "kind".
const (
	EntityKindAgent = "agent"
	EntityKindHuman = "human"
)

// Admission is what an auth mount verified about one credential. The auth
// method builds it at login and core completes it in LoginCreateToken (it sets
// MountPath) before the token is stored; from then on it is never written.
//
// One *Admission is shared by pointer: the token store keeps it on the stored
// TokenEntry, and every per-request copy of that entry holds the same pointer.
// Readers on any number of goroutines need no lock because nothing in it
// changes after LoginCreateToken.
type Admission struct {
	// MountPath is the admitting mount's path relative to its namespace
	// ("auth/jwt/", never "ns1/auth/jwt/"), answered as the fact "mount".
	MountPath string

	// Facts are the raw verified facts, keyed by the names the credential
	// carries (claims, certificate or service-account fields). They are never
	// renamed: names reach them only through the mount's Mapping.
	Facts selector.Facts

	// Mount is the admitting mount's live naming, shared with every other
	// admission of that mount, so a mapping edit reaches cached admissions.
	Mount *MountFacts

	// IssuedAt is when the credential was issued, when it says so; zero
	// otherwise.
	IssuedAt time.Time
}

// MountFacts is owned by one auth mount and shared by pointer with every
// admission the mount produces. The mount stores a new *MountNaming in Current
// whenever it installs a configuration (a config write, setup, load); readers
// load it without a lock. A published MountNaming is never modified, so a
// reader sees either the old naming or the new one, whole.
type MountFacts struct {
	Current atomic.Pointer[MountNaming]
}

// Load returns the naming in force, or nil when m is nil or the mount has not
// published one.
func (m *MountFacts) Load() *MountNaming {
	if m == nil {
		return nil
	}
	return m.Current.Load()
}

// MountNaming is how one mount configuration names its facts: the canonical
// names it answers and the kind of entity it admits. It is immutable.
type MountNaming struct {
	Mapping *selector.Mapping // built-in and mapped fact names
	Kind    string            // EntityKindAgent or EntityKindHuman
}

// NewMountNaming returns a naming for mapping and kind. An empty kind is
// EntityKindAgent.
func NewMountNaming(mapping *selector.Mapping, kind string) *MountNaming {
	if kind == "" {
		kind = EntityKindAgent
	}
	return &MountNaming{Mapping: mapping, Kind: kind}
}

// Lookup answers the canonical fact name against naming n: "mount" from the
// admission, "kind" from n, and any other name through n's Mapping into Facts.
// A name the mapping does not answer is invisible and yields an empty Cursor,
// as does a nil admission or naming. Callers load n once (Mount.Load()) and
// pass it to every lookup of one evaluation, so all of them see one naming.
// Lookup does not allocate.
func (a *Admission) Lookup(n *MountNaming, name string) selector.Cursor {
	if a == nil || n == nil {
		return selector.Cursor{}
	}
	switch name {
	case selector.NameMount:
		if a.MountPath == "" {
			return selector.Cursor{}
		}
		return selector.One(a.MountPath)
	case selector.NameKind:
		if n.Kind == "" {
			return selector.Cursor{}
		}
		return selector.One(n.Kind)
	}
	if a.Facts == nil {
		return selector.Cursor{}
	}
	key, ok := n.Mapping.Resolve(name)
	if !ok {
		return selector.Cursor{}
	}
	return a.Facts.Lookup(key)
}

// RenderMetadata renders the facts n maps (not the built-ins, unless mapped to
// themselves) as token metadata: each value through selector.FormatScalar, the
// values of a multi-valued fact joined with commas. A fact the admission does
// not carry is left out. It returns nil when nothing is rendered.
func RenderMetadata(n *MountNaming, a *Admission) map[string]string {
	if n == nil || a == nil {
		return nil
	}
	var out map[string]string
	var buf []byte
	for _, name := range n.Mapping.Mapped() {
		cur := a.Lookup(n, name)
		// Probe a copy: a present fact may render as "", an absent one is skipped.
		if probe := cur; !hasValue(&probe) {
			continue
		}
		buf = selector.AppendValues(buf[:0], &cur, ',')
		if out == nil {
			out = make(map[string]string, len(n.Mapping.Mapped()))
		}
		out[name] = string(buf)
	}
	return out
}

func hasValue(c *selector.Cursor) bool {
	_, ok := c.Next()
	return ok
}
