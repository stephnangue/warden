package logical

import "strings"

// PolicyNameRule states the rule CanonicalPolicyName enforces, for error
// messages.
const PolicyNameRule = `lowercase letters, digits, "_", "-" and ".", starting and ending with a letter, digit or "_"`

// CanonicalPolicyName returns the one spelling a policy is stored, cached and
// attached under, and whether name has one. Surrounding space is trimmed and
// ASCII letters are lower-cased; what is left must be a single path segment of
// lowercase letters, digits, "_", "-" and ".", starting and ending with a
// letter, digit or "_". That is the policy routes' own name pattern, so every
// storable name has a canonical form and nothing else does: a "/" or a ".."
// can never reach a cache or storage key.
//
// Only ASCII is folded. A non-ASCII letter is refused rather than lower-cased,
// since Unicode folding maps some of them onto ASCII ("İ" to "i", the Kelvin
// sign to "k") and would give a policy a second spelling.
//
// It runs for every policy of every request, so it does not allocate when name
// is already canonical.
func CanonicalPolicyName(name string) (string, bool) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", false
	}
	last := len(name) - 1
	upper := false
	for i := 0; i <= last; i++ {
		c := name[i]
		switch {
		case 'a' <= c && c <= 'z', '0' <= c && c <= '9', c == '_':
		case 'A' <= c && c <= 'Z':
			upper = true
		case (c == '-' || c == '.') && i != 0 && i != last:
		default:
			return "", false
		}
	}
	if upper {
		// ASCII only by now, so this folds A-Z and nothing else.
		name = strings.ToLower(name)
	}
	return name, true
}
