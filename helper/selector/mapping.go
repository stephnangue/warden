package selector

import (
	"fmt"
	"slices"
)

// Mapping is what one mount publishes: the canonical fact names its admissions
// answer, each with the raw Key it reads. It holds the mount's built-in names,
// which read the raw fact of the same name, and the names the operator mapped.
// A Mapping is compiled when the mount's configuration is written or loaded,
// is immutable afterwards, and is shared by pointer with every admission the
// mount produces. Its slice accessors return the Mapping's own slices: callers
// must treat them as read-only.
type Mapping struct {
	names  map[string]Key
	all    []string // built-in and mapped names, sorted
	mapped []string // mapped names only, sorted
}

// CompileMapping builds a mount's Mapping. builtins are the names the auth
// method always answers. facts maps a raw source key (a name or a JSON pointer,
// see ParseKey) to the canonical name it is published as, at most
// MaxMappingEntries of them.
//
// Every name must pass ValidateName and must not be "mount" or "kind". A mapped
// name may equal a built-in only when its source is that same built-in (the
// identity mapping "sub": "sub", which adds a built-in to the mapped names), and
// two sources may not publish one name.
func CompileMapping(builtins []string, facts map[string]string) (*Mapping, error) {
	if len(facts) > MaxMappingEntries {
		return nil, fmt.Errorf("at most %d facts can be mapped, got %d", MaxMappingEntries, len(facts))
	}
	m := &Mapping{names: make(map[string]Key, len(builtins)+len(facts))}
	builtin := make(map[string]bool, len(builtins))
	for _, name := range builtins {
		if err := ValidateName(name); err != nil {
			return nil, fmt.Errorf("built-in fact: %w", err)
		}
		if IsReserved(name) {
			return nil, fmt.Errorf("built-in fact %q is reserved", name)
		}
		if builtin[name] {
			return nil, fmt.Errorf("built-in fact %q is listed twice", name)
		}
		builtin[name] = true
		m.names[name] = Key{Name: name}
	}

	// Visit sources in order so the error for a name with two sources is stable.
	sources := make([]string, 0, len(facts))
	for source := range facts {
		sources = append(sources, source)
	}
	slices.Sort(sources)
	sourceOf := make(map[string]string, len(facts))
	for _, source := range sources {
		target := facts[source]
		key, err := ParseKey(source)
		if err != nil {
			return nil, fmt.Errorf("fact %q: %w", target, err)
		}
		if err := ValidateName(target); err != nil {
			return nil, fmt.Errorf("fact source %q: %w", source, err)
		}
		if IsReserved(target) {
			return nil, fmt.Errorf("fact source %q: %q is reserved for every mount and cannot be mapped", source, target)
		}
		if prev, ok := sourceOf[target]; ok {
			return nil, fmt.Errorf("fact %q is produced by both %q and %q", target, prev, source)
		}
		if builtin[target] && source != target {
			return nil, fmt.Errorf("fact source %q: %q is a built-in fact on this mount; only %q can map to it", source, target, target)
		}
		sourceOf[target] = source
		m.names[target] = key
		m.mapped = append(m.mapped, target)
	}
	slices.Sort(m.mapped)

	m.all = make([]string, 0, len(m.names))
	for name := range m.names {
		m.all = append(m.all, name)
	}
	slices.Sort(m.all)
	return m, nil
}

// Resolve returns the raw Key a canonical name reads, and whether the mount
// answers that name at all. A nil Mapping answers nothing.
func (m *Mapping) Resolve(name string) (Key, bool) {
	if m == nil {
		return Key{}, false
	}
	k, ok := m.names[name]
	return k, ok
}

// Names returns every name the mount answers, built-in and mapped, sorted. The
// reserved names are not included. The slice is shared and must not be
// modified.
func (m *Mapping) Names() []string {
	if m == nil {
		return nil
	}
	return m.all
}

// Mapped returns the names the operator mapped, sorted, including identity
// mappings of built-ins: the names a mount publishes beyond matching. The slice
// is shared and must not be modified.
func (m *Mapping) Mapped() []string {
	if m == nil {
		return nil
	}
	return m.mapped
}
