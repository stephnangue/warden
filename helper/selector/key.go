// Package selector matches what an auth mount verified about a credential
// against operator-written rules, the rules a group uses to grant roles.
//
// A mount verifies a credential into Facts and publishes a Mapping from
// canonical fact names to the raw keys inside those facts. A rule is a set of
// selectors, each a fact name with the values it may take. A compiled Rule
// asks a Source, facts seen through a mapping, for each name its selectors
// list, and matches when every selector's name yields at least one value equal
// to, or matched by, one of that selector's values.
//
// Everything here is built once, when a mount or a group is written, and is
// immutable afterwards, so it is safe to share across goroutines without locks.
// Matching is on the request path and does not allocate: cursors are returned
// by value, numbers and booleans are rendered into a stack buffer, and globs are
// matched by a backtracking matcher over the bytes in place.
//
// The package imports only the standard library, so every layer of the server
// can use it.
package selector

import (
	"errors"
	"fmt"
	"strings"
)

// Key names one raw fact inside a Facts value: a claim or field name, or an
// RFC 6901 JSON pointer into nested claims ("/deployment/env"). Path is non-nil
// exactly when Name starts with '/', and holds the pointer's unescaped tokens.
// A Key is parsed once, when a mapping is compiled, and never on the request
// path.
type Key struct {
	Name string
	Path []string
}

// IsPointer reports whether k is a JSON pointer rather than a plain name.
func (k Key) IsPointer() bool { return k.Path != nil }

// ParseKey parses a raw fact key. A key not starting with '/' is a plain name
// taken as is, so names such as "https://example.com/env" work unchanged. A key
// starting with '/' is a JSON pointer: it is split on '/' and each token has
// "~1" turned into '/' and "~0" into '~'; any other use of '~' is refused. The
// pointer "/" names the top-level key "". A top-level name that itself starts
// with '/' is therefore unreachable.
func ParseKey(s string) (Key, error) {
	if s == "" {
		return Key{}, errors.New("empty fact key")
	}
	if s[0] != '/' {
		return Key{Name: s}, nil
	}
	tokens := strings.Split(s[1:], "/")
	for i, tok := range tokens {
		if strings.IndexByte(tok, '~') < 0 {
			continue
		}
		unescaped, err := unescapePointerToken(tok)
		if err != nil {
			return Key{}, fmt.Errorf("fact key %q: %w", s, err)
		}
		tokens[i] = unescaped
	}
	return Key{Name: s, Path: tokens}, nil
}

// unescapePointerToken decodes one RFC 6901 reference token left to right, so
// "~01" becomes "~1" and never "/".
func unescapePointerToken(tok string) (string, error) {
	var b strings.Builder
	b.Grow(len(tok))
	for i := 0; i < len(tok); i++ {
		c := tok[i]
		if c != '~' {
			b.WriteByte(c)
			continue
		}
		if i+1 == len(tok) {
			return "", errors.New(`"~" must be followed by "0" or "1"`)
		}
		switch tok[i+1] {
		case '0':
			b.WriteByte('~')
		case '1':
			b.WriteByte('/')
		default:
			return "", errors.New(`"~" must be followed by "0" or "1"`)
		}
		i++
	}
	return b.String(), nil
}

// Limits on names, rules and mappings.
const (
	// MaxNameLen bounds a canonical fact name, in bytes.
	MaxNameLen = 64
	// MaxRuleNames bounds the selectors of one rule (one fact name each).
	MaxRuleNames = 32
	// MaxRuleValues bounds the values of one selector.
	MaxRuleValues = 32
	// MaxValueLen bounds one rule value, in bytes.
	MaxValueLen = 1024
	// MaxMappingEntries bounds the facts one mount maps.
	MaxMappingEntries = 32
	// MaxTableFields bounds the fields of a Table.
	MaxTableFields = 16
)

// Names every admission answers whatever its mount maps. They cannot be mapped.
const (
	// NameMount is the admitting mount's path.
	NameMount = "mount"
	// NameKind is the kind of entity the mount admits.
	NameKind = "kind"
)

// IsReserved reports whether name is answered by every admission and so can
// be neither mapped nor offered as a built-in by a mount.
func IsReserved(name string) bool { return name == NameMount || name == NameKind }

// ValidateName checks a canonical fact name: 1 to MaxNameLen bytes of
// a-z, 0-9 and _ . : / -, not starting with '/' (which would read as a JSON
// pointer).
func ValidateName(name string) error {
	if name == "" {
		return errors.New("empty fact name")
	}
	if len(name) > MaxNameLen {
		return fmt.Errorf("fact name %q is longer than %d bytes", name, MaxNameLen)
	}
	if name[0] == '/' {
		return fmt.Errorf("fact name %q must not start with \"/\"", name)
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '_', c == '.', c == ':', c == '/', c == '-':
		default:
			return fmt.Errorf("fact name %q may contain only a-z, 0-9 and _ . : / -", name)
		}
	}
	return nil
}
