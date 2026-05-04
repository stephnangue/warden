package helpers

import (
	"fmt"
	"strings"
)

// ValidatePath checks that p is well-formed for the warden CLI's generic
// read/write/list/delete commands. It rejects the obvious LLM-hallucination
// classes — absolute paths, traversal, control characters, URL-reserved
// punctuation, and percent-encoding — at the CLI boundary, before any HTTP
// call. All errors wrap ErrInvalidInput so the central renderer maps them to
// exit code 3.
func ValidatePath(p string) error {
	if p == "" {
		return fmt.Errorf("path is empty: %w", ErrInvalidInput)
	}
	if strings.TrimSpace(p) != p {
		return fmt.Errorf("path %q has leading or trailing whitespace: %w", p, ErrInvalidInput)
	}
	if strings.HasPrefix(p, "/") {
		return fmt.Errorf("path %q is absolute (warden paths are relative, e.g. \"aws/config\"): %w", p, ErrInvalidInput)
	}
	if strings.ContainsRune(p, '%') {
		return fmt.Errorf("path %q contains '%%' (paths must not be percent-encoded; pass raw bytes): %w", p, ErrInvalidInput)
	}

	for i := 0; i < len(p); i++ {
		b := p[i]
		if b < 0x20 || b == 0x7f {
			return fmt.Errorf("path %q contains control character (byte 0x%02x at position %d): %w", p, b, i, ErrInvalidInput)
		}
		if b == '?' || b == '#' {
			return fmt.Errorf("path %q contains URL-reserved character %q (use --output / --fields for query-like behavior): %w", p, b, ErrInvalidInput)
		}
	}

	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return fmt.Errorf("path %q contains traversal segment '..': %w", p, ErrInvalidInput)
		}
	}

	return nil
}

// ValidateHeaderValue checks that v is safe to send as an HTTP header value
// (used for `--namespace`/`--role` which become X-Warden-Namespace and
// X-Warden-Role headers). Rejects CR/LF (header injection), other control
// characters, and leading/trailing whitespace. Empty is allowed since callers
// treat it as "absent."
func ValidateHeaderValue(name, v string) error {
	if v == "" {
		return nil
	}
	if strings.TrimSpace(v) != v {
		return fmt.Errorf("%s value %q has leading or trailing whitespace: %w", name, v, ErrInvalidInput)
	}
	for i := 0; i < len(v); i++ {
		b := v[i]
		if b < 0x20 || b == 0x7f {
			return fmt.Errorf("%s value %q contains control character (byte 0x%02x at position %d): %w", name, v, b, i, ErrInvalidInput)
		}
	}
	return nil
}

// ValidateIdentifier checks that v is a well-formed single-segment identifier
// (used for `--type` flag values that go into JSON bodies or URL segments).
// Rejects empty, whitespace, slashes (use ValidatePath for multi-segment), and
// the same control/percent-encoding hazards as ValidatePath.
func ValidateIdentifier(name, v string) error {
	if v == "" {
		return fmt.Errorf("%s is empty: %w", name, ErrInvalidInput)
	}
	if strings.TrimSpace(v) != v {
		return fmt.Errorf("%s %q has leading or trailing whitespace: %w", name, v, ErrInvalidInput)
	}
	if strings.ContainsRune(v, '%') {
		return fmt.Errorf("%s %q contains '%%' (must not be percent-encoded): %w", name, v, ErrInvalidInput)
	}
	for i := 0; i < len(v); i++ {
		b := v[i]
		if b < 0x20 || b == 0x7f {
			return fmt.Errorf("%s %q contains control character (byte 0x%02x at position %d): %w", name, v, b, i, ErrInvalidInput)
		}
		if b == '/' {
			return fmt.Errorf("%s %q must be a single segment (no '/'): %w", name, v, ErrInvalidInput)
		}
		if b == '?' || b == '#' {
			return fmt.Errorf("%s %q contains URL-reserved character %q: %w", name, v, b, ErrInvalidInput)
		}
	}
	return nil
}
