package helper

import (
	"fmt"
	"strings"
)

// MatchPattern checks whether a value matches a segment-aware wildcard pattern.
//
// Both value and pattern are split by "/" into segments and compared segment
// by segment. If both contain "://", the scheme must match exactly and segment
// matching applies to the portion after "://". If neither contains "://",
// the full strings are compared as segments. A mismatch in scheme presence
// (one has "://", the other does not) always returns false.
//
// Wildcard syntax (mirrors CBP policy segment wildcards):
//   - "+"  matches exactly one segment
//   - "*"  as the last segment matches one or more remaining segments
//   - "+*" is forbidden
//   - all other segments require an exact match
//
// Examples:
//
//	MatchPattern("spiffe://example.com/dept/svc", "spiffe://+/dept/svc")             // true
//	MatchPattern("spiffe://example.com/dept/team/svc", "spiffe://example.com/dept/*") // true
//	MatchPattern("spiffe://anything/any/path", "spiffe://*")                          // true
//	MatchPattern("example.com/dept/svc", "+/dept/svc")                                // true
//	MatchPattern("example.com/dept/team/svc", "example.com/dept/*")                   // true
func MatchPattern(value, pattern string) bool {
	valScheme, valBody := parseScheme(value)
	patScheme, patBody := parseScheme(pattern)

	if valScheme != patScheme {
		return false
	}

	// "scheme://*" or bare "*" — matches everything with the same scheme
	if patBody == "*" {
		return true
	}

	return matchSegments(strings.Split(valBody, "/"), strings.Split(patBody, "/"))
}

// matchSegments compares value segments against pattern segments using
// "+" (single-segment wildcard) and trailing "*" (prefix wildcard).
func matchSegments(valParts, patParts []string) bool {
	isPrefix := len(patParts) > 0 && patParts[len(patParts)-1] == "*"
	if isPrefix {
		patParts = patParts[:len(patParts)-1]
	}

	if !isPrefix && len(valParts) != len(patParts) {
		return false
	}
	// With prefix (*): value must have strictly more segments than the
	// pattern prefix — the wildcard matches one or more segments.
	if isPrefix && len(valParts) <= len(patParts) {
		return false
	}

	for i, pp := range patParts {
		if pp != "+" && pp != valParts[i] {
			return false
		}
	}
	return true
}

// MatchAny checks whether a value matches any of the given patterns.
func MatchAny(value string, patterns []string) bool {
	for _, p := range patterns {
		if MatchPattern(value, p) {
			return true
		}
	}
	return false
}

// ValidatePattern checks that a pattern is well-formed for use with MatchPattern.
func ValidatePattern(pattern string) error {
	if strings.Contains(pattern, "+*") {
		return fmt.Errorf("pattern %q: '+*' is forbidden", pattern)
	}

	_, body := parseScheme(pattern)
	if body == "" {
		return fmt.Errorf("pattern %q: empty body", pattern)
	}

	// "scheme://*" or bare "*" — valid catch-all
	if body == "*" {
		return nil
	}

	parts := strings.Split(body, "/")
	for i, p := range parts {
		if p == "" {
			return fmt.Errorf("pattern %q: empty segment at position %d", pattern, i)
		}
		if p == "*" && i != len(parts)-1 {
			return fmt.Errorf("pattern %q: '*' is only allowed as the last segment", pattern)
		}
	}
	return nil
}

// parseScheme splits a string at "://". If the separator is absent, scheme is
// empty and body is the full string — this lets callers treat scheme-less
// values and patterns uniformly (both yield empty scheme, so they compare equal).
func parseScheme(s string) (scheme, body string) {
	if idx := strings.Index(s, "://"); idx >= 0 {
		return s[:idx], s[idx+3:]
	}
	return "", s
}
