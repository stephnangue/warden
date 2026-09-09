package credential

import (
	"iter"
	"maps"
	"strings"
)

// Config is an immutable view of a credential configuration map.
//
// A CredSpec or CredSource handed out by the config store is shared: the store
// returns the pointer it caches, and every concurrent mint reads through it. The
// map inside a Config is unreachable from outside this package, so a published
// config cannot be written into by the code that reads it — the compiler refuses
// rather than a comment asking. That rule used to live in exactly one comment, at
// one call site, and the rotation manager was already breaking it.
//
// Config is a value wrapping a single map header: passing it copies one word and
// allocates nothing, and Get compiles to the same map access the raw map did. The
// cost of immutability sits on the write path instead, where a new map is built
// once per rotation or config update rather than once per request.
//
// The zero value is usable and empty.
type Config struct{ m map[string]string }

// NewConfig returns a Config holding a copy of m.
//
// The copy is the point: without it "the caller must not retain m" would be
// another convention, which is what this type exists to remove. Callers hand over
// a map they built and it stops being reachable.
func NewConfig(m map[string]string) Config {
	return Config{m: maps.Clone(m)}
}

// Get returns the value for key, or "" if absent.
func (c Config) Get(key string) string {
	return c.m[key]
}

// Lookup returns the value for key and whether it was present. Use it where a
// stored empty string has to be distinguished from an absent key — several
// validators treat present-but-empty differently from unset.
func (c Config) Lookup(key string) (string, bool) {
	v, ok := c.m[key]
	return v, ok
}

// Len returns the number of keys.
func (c Config) Len() int {
	return len(c.m)
}

// All iterates the keys and values in unspecified order.
func (c Config) All() iter.Seq2[string, string] {
	return maps.All(c.m)
}

// Equal reports whether two configs hold the same keys and values.
func (c Config) Equal(other Config) bool {
	return maps.Equal(c.m, other.m)
}

// With returns a copy carrying key=value. The receiver is unchanged.
func (c Config) With(key, value string) Config {
	next := maps.Clone(c.m)
	if next == nil {
		next = make(map[string]string, 1)
	}
	next[key] = value
	return Config{m: next}
}

// WithAll returns a copy with every entry of overrides applied over the receiver.
func (c Config) WithAll(overrides map[string]string) Config {
	next := maps.Clone(c.m)
	if next == nil {
		next = make(map[string]string, len(overrides))
	}
	maps.Copy(next, overrides)
	return Config{m: next}
}

// Without returns a copy with the named keys removed.
func (c Config) Without(keys ...string) Config {
	next := maps.Clone(c.m)
	for _, k := range keys {
		delete(next, k)
	}
	return Config{m: next}
}

// Prefixed returns the entries whose keys carry the given prefix, with the prefix
// stripped.
func (c Config) Prefixed(prefix string) map[string]string {
	out := make(map[string]string)
	for k, v := range c.m {
		if after, found := strings.CutPrefix(k, prefix); found {
			out[after] = v
		}
	}
	return out
}

// Map returns a copy of the underlying map.
//
// It is a boundary escape hatch and allocates on every call, so it belongs only
// where a plain map genuinely has to leave: the storage DTOs, the HTTP response
// payloads, and the staged maps a rotation entry serializes. Anywhere else, a
// Config should be passed instead — a Map() call on a request path is a mistake.
func (c Config) Map() map[string]string {
	return maps.Clone(c.m)
}
