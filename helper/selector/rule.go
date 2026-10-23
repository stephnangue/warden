package selector

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Source answers a canonical fact name with the values it holds: an
// admission seen through its mount's Mapping, plus the names every admission
// answers. A name the source cannot answer yields an empty Cursor.
type Source interface {
	Lookup(name string) Cursor
}

// Rule is one compiled selector: for every name it lists, the source must yield
// at least one value equal to, or matched by, one of the rule's values for that
// name. A Rule is immutable and safe for concurrent use.
type Rule struct {
	keys  []ruleKey // sorted by name
	names []string  // the keys' names, in the same order
}

// Names returns the fact names r lists, sorted. The slice is shared and must not
// be modified.
func (r *Rule) Names() []string {
	if r == nil {
		return nil
	}
	return r.names
}

type ruleKey struct {
	name   string
	values []ruleValue // exact values first, then globs
}

// ruleValue is an exact value (glob nil) or a glob.
type ruleValue struct {
	lit  string
	glob *Glob
}

// Compile compiles a selector: fact name to the values it may take. A value is
// exact unless it holds an unescaped '*' or '?', which makes it a glob; in an
// exact value "\x" stands for x. The selector must list at least one name, at
// most MaxRuleNames, each valid (ValidateName) with 1 to MaxRuleValues
// non-empty values of at most MaxValueLen bytes. Duplicate values collapse.
func Compile(s map[string][]string) (*Rule, error) {
	if len(s) == 0 {
		return nil, errors.New("a selector must list at least one fact")
	}
	if len(s) > MaxRuleNames {
		return nil, fmt.Errorf("a selector lists at most %d facts, got %d", MaxRuleNames, len(s))
	}
	r := &Rule{keys: make([]ruleKey, 0, len(s))}
	for name, values := range s {
		if err := ValidateName(name); err != nil {
			return nil, err
		}
		if len(values) == 0 {
			return nil, fmt.Errorf("fact %q: at least one value is required", name)
		}
		if len(values) > MaxRuleValues {
			return nil, fmt.Errorf("fact %q: at most %d values, got %d", name, MaxRuleValues, len(values))
		}
		rk, err := compileValues(name, values)
		if err != nil {
			return nil, err
		}
		r.keys = append(r.keys, rk)
	}
	slices.SortFunc(r.keys, func(a, b ruleKey) int { return strings.Compare(a.name, b.name) })
	r.names = make([]string, len(r.keys))
	for i := range r.keys {
		r.names[i] = r.keys[i].name
	}
	return r, nil
}

func compileValues(name string, values []string) (ruleKey, error) {
	sorted := slices.Clone(values)
	slices.Sort(sorted)
	sorted = slices.Compact(sorted)

	rk := ruleKey{name: name, values: make([]ruleValue, 0, len(sorted))}
	var globs []ruleValue
	for _, v := range sorted {
		if v == "" {
			return ruleKey{}, fmt.Errorf("fact %q: empty value", name)
		}
		if len(v) > MaxValueLen {
			return ruleKey{}, fmt.Errorf("fact %q: a value is longer than %d bytes", name, MaxValueLen)
		}
		if IsPattern(v) {
			g, err := CompileGlob(v)
			if err != nil {
				return ruleKey{}, fmt.Errorf("fact %q: value %q: %w", name, v, err)
			}
			globs = append(globs, ruleValue{glob: g})
			continue
		}
		lit, err := Unescape(v)
		if err != nil {
			return ruleKey{}, fmt.Errorf("fact %q: value %q: %w", name, v, err)
		}
		// "a" and "\a" write the same exact value.
		if !slices.ContainsFunc(rk.values, func(rv ruleValue) bool { return rv.lit == lit }) {
			rk.values = append(rk.values, ruleValue{lit: lit})
		}
	}
	rk.values = append(rk.values, globs...)
	return rk, nil
}

// Match reports whether src satisfies r. A name src cannot answer, or answers
// with no scalar value, fails the rule. A nil or empty Rule matches nothing.
// Match does not allocate beyond what src.Lookup does.
func (r *Rule) Match(src Source) bool {
	if r == nil || len(r.keys) == 0 {
		return false
	}
	for i := range r.keys {
		rk := &r.keys[i]
		cur := src.Lookup(rk.name)
		if !rk.matches(&cur) {
			return false
		}
	}
	return true
}

// matches reports whether any value cur yields satisfies any of rk's values.
func (rk *ruleKey) matches(cur *Cursor) bool {
	for v, ok := cur.Next(); ok; v, ok = cur.Next() {
		if v.Kind == KindString {
			for j := range rk.values {
				if rk.values[j].matchString(v.S) {
					return true
				}
			}
			continue
		}
		// Matching is type-blind: a number or boolean is compared through its
		// one rendering, built on the stack.
		var buf [32]byte
		b := FormatScalar(buf[:0], v)
		if len(b) == 0 {
			continue
		}
		for j := range rk.values {
			if rk.values[j].matchBytes(b) {
				return true
			}
		}
	}
	return false
}

func (rv *ruleValue) matchString(s string) bool {
	if rv.glob != nil {
		return rv.glob.Match(s)
	}
	return s == rv.lit
}

func (rv *ruleValue) matchBytes(b []byte) bool {
	if rv.glob != nil {
		return rv.glob.MatchBytes(b)
	}
	return string(b) == rv.lit
}
