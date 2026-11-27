package helper

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/hashicorp/go-secure-stdlib/parseutil"

	"github.com/stephnangue/warden/helper/selector"
	"github.com/stephnangue/warden/logical"
)

// Bounds on mfa_options.reauthenticate_after. The warden CLI reuses a stored
// session only while more than five minutes of it remain, so a shorter bound
// would issue sessions it never reuses; the longest is the longest session an
// auth mount issues.
const (
	MinReauthenticateAfter = 5 * time.Minute
	MaxReauthenticateAfter = 8 * time.Hour
)

// MFAOptions is an auth mount's mfa_options, as storage holds it: a floor over
// the mount's facts (Require) and a bound on how long ago the holder of a
// credential authenticated (ReauthenticateAfter). Require is kept as written,
// values in the order listed, for a mount that asks its identity provider for
// them; Attach compiles it. An MFAOptions is not modified once its config is
// built.
type MFAOptions struct {
	// Require maps a fact name the mount publishes to the values it accepts:
	// a group rule's shape, without "mount". Every name must match, by any one
	// of its values. Nil for no floor.
	Require map[string][]string `json:"require,omitempty"`

	// ReauthenticateAfter is how long after the holder authenticated a
	// credential stops being accepted; 0 for no bound.
	ReauthenticateAfter time.Duration `json:"reauthenticate_after,omitempty"`
}

// ParseMFAOptions converts the mfa_options field of a config write: an object
// with require, reauthenticate_after or both. nil or an empty object clears
// the block, and returns nil. reauthenticate_after takes a duration string
// ("15m") or a number of seconds, between MinReauthenticateAfter and
// MaxReauthenticateAfter. Whether require names facts the mount publishes is
// Attach's check, against the mapping the write installs.
func ParseMFAOptions(raw any) (*MFAOptions, error) {
	if raw == nil {
		return nil, nil
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("mfa_options: must be an object with require, reauthenticate_after or both, got %T", raw)
	}
	if len(m) == 0 {
		return nil, nil
	}
	o := &MFAOptions{}
	for _, key := range slices.Sorted(maps.Keys(m)) {
		switch key {
		case "require":
			rule, err := selector.ParseRule(m[key])
			if err != nil {
				return nil, fmt.Errorf("mfa_options.require: %w", err)
			}
			if len(rule) == 0 {
				return nil, errors.New("mfa_options.require: name at least one fact, or leave require out for no floor")
			}
			o.Require = rule
		case "reauthenticate_after":
			d, err := parseutil.ParseDurationSecond(m[key])
			if err != nil {
				return nil, fmt.Errorf("mfa_options.reauthenticate_after: %w", err)
			}
			if err := checkReauthenticateAfter(d); err != nil {
				return nil, err
			}
			o.ReauthenticateAfter = d
		default:
			return nil, fmt.Errorf("mfa_options: unknown key %q; it takes require and reauthenticate_after", key)
		}
	}
	return o, nil
}

func checkReauthenticateAfter(d time.Duration) error {
	if d < MinReauthenticateAfter || d > MaxReauthenticateAfter {
		return fmt.Errorf("mfa_options.reauthenticate_after must be between %s and %s, got %s; "+
			"leave it out for no bound", MinReauthenticateAfter, MaxReauthenticateAfter, d)
	}
	return nil
}

// Attach compiles o against the mapping of n, a naming its mount has not
// published yet, and sets the result as n's MFA requirement. It returns why o
// does not compile, or nil. On failure n still gets a requirement, one that
// admits nothing (logical.MFARequirement.Invalid): a stored block that no
// longer compiles at load must refuse every credential rather than none. A nil
// o leaves n without one. A nil n, the naming of a mount whose facts do not
// compile, is left alone: such a mount admits nothing already.
func (o *MFAOptions) Attach(n *logical.MountNaming) error {
	if n == nil {
		return nil
	}
	n.MFA = nil
	if o == nil {
		return nil
	}
	r, err := o.compile(n.Mapping)
	if err != nil {
		n.MFA = &logical.MFARequirement{Invalid: err}
		return err
	}
	n.MFA = r
	return nil
}

func (o *MFAOptions) compile(m *selector.Mapping) (*logical.MFARequirement, error) {
	if len(o.Require) == 0 && o.ReauthenticateAfter == 0 {
		return nil, errors.New("mfa_options: set require, reauthenticate_after or both; an empty object clears mfa_options")
	}
	r := &logical.MFARequirement{}
	if o.ReauthenticateAfter != 0 {
		if err := checkReauthenticateAfter(o.ReauthenticateAfter); err != nil {
			return nil, err
		}
		r.ReauthenticateAfter = o.ReauthenticateAfter
	}
	if len(o.Require) == 0 {
		return r, nil
	}
	rule, err := selector.Compile(o.Require)
	if err != nil {
		return nil, fmt.Errorf("mfa_options.require: %w", err)
	}
	for _, name := range rule.Names() {
		if _, ok := slices.BinarySearch(m.Names(), name); !ok {
			return nil, fmt.Errorf("mfa_options.require: %q is not a fact this mount publishes (one of %s); "+
				"map the claim in facts first", name, strings.Join(m.Names(), ", "))
		}
	}
	r.Rule = rule
	return r, nil
}

// Warnings returns what a config write setting o is told: each value of
// require that is a pattern, which is matched but never asked of the identity
// provider, and whose "*" does not cross "/". Nil when there is nothing to
// say.
func (o *MFAOptions) Warnings() []string {
	if o == nil {
		return nil
	}
	var out []string
	for _, name := range slices.Sorted(maps.Keys(o.Require)) {
		for _, v := range o.Require[name] {
			if selector.IsPattern(v) {
				out = append(out, fmt.Sprintf("mfa_options.require: %q (fact %q) is a pattern: it is matched, "+
					"never asked of the identity provider, and its \"*\" stops at \"/\" (\"**\" crosses it)", v, name))
			}
		}
	}
	return out
}
