package helpers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"sort"
	"strings"
)

// ResolveJSONInput parses the value of a `-json` flag in three forms:
//
//	literal :  -json '{"type":"aws","region":"us-east-1"}'
//	file    :  -json @aws-source.json
//	stdin   :  -json -                                   (use with `<` or `|`)
//
// Returns (nil, nil) when v is empty so callers can branch on
// "no -json was provided" without a separate flag check. Errors are
// wrapped with ErrInvalidInput so the central renderer maps them to
// exit code 3.
//
// JSON null at the root is rejected (treating it as "no payload" would
// silently fall through to typed-flag mode and confuse the user).
// `-json -` with stdin attached to a terminal is rejected upfront so
// the user isn't stuck at a blocking ReadAll waiting for EOF.
func ResolveJSONInput(v string) (map[string]any, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, nil
	}

	var raw []byte
	var err error
	switch {
	case v == "-":
		if stat, statErr := os.Stdin.Stat(); statErr == nil && (stat.Mode()&os.ModeCharDevice) != 0 {
			return nil, fmt.Errorf("-json -: stdin is a terminal; pipe a payload via `<` or `|`: %w", ErrInvalidInput)
		}
		raw, err = io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("-json -: read stdin: %w", err)
		}
	case strings.HasPrefix(v, "@"):
		path := v[1:]
		raw, err = os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("-json @%s: %w", path, err)
		}
	default:
		raw = []byte(v)
	}

	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, fmt.Errorf("-json input is empty: %w", ErrInvalidInput)
	}

	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, fmt.Errorf("-json: invalid JSON (%v): %w", err, ErrInvalidInput)
	}
	if data == nil {
		// JSON `null` at the root unmarshals into a nil map, which would
		// silently fall through to typed-flag mode. Reject explicitly.
		return nil, fmt.Errorf("-json: payload cannot be null: %w", ErrInvalidInput)
	}
	return data, nil
}

// RejectFlagsWithJSON returns ErrUsage if any of `flags` (a map of
// human-readable flag names → "this flag was set") is true AND -json was
// also provided. The combination is ambiguous — pick one input mode per
// command. Flag names in the resulting error are sorted for deterministic
// output (map iteration order is otherwise non-stable).
func RejectFlagsWithJSON(jsonProvided bool, flags map[string]bool) error {
	if !jsonProvided {
		return nil
	}
	conflicting := make([]string, 0, len(flags))
	for name, set := range flags {
		if set {
			conflicting = append(conflicting, name)
		}
	}
	if len(conflicting) == 0 {
		return nil
	}
	sort.Strings(conflicting)
	return fmt.Errorf("-json cannot be combined with %s: %w",
		strings.Join(conflicting, ", "), ErrUsage)
}

// ResolvePath returns the explicit path from either the positional
// argument or the -path flag, with a usage error when both are
// supplied. Returns "" when neither is set — callers may then fall
// back to deriving the path (e.g. from -type or from a JSON payload's
// "type" field), or treat empty as a usage error.
func ResolvePath(args []string, pathFlag string) (string, error) {
	if len(args) > 0 && pathFlag != "" {
		return "", fmt.Errorf(
			"cannot specify both -path=%q and positional PATH %q: %w",
			pathFlag, args[0], ErrUsage)
	}
	if len(args) > 0 {
		return args[0], nil
	}
	return pathFlag, nil
}

// RequirePath is ResolvePath plus a usage error when neither source
// supplied a value. Use this in commands where PATH is mandatory
// (disable, read, etc.). Commands that fall back to deriving the path
// from -type or a JSON payload should call ResolvePath directly and
// handle the empty case themselves.
func RequirePath(args []string, pathFlag string) (string, error) {
	path, err := ResolvePath(args, pathFlag)
	if err != nil {
		return "", err
	}
	if path == "" {
		return "", fmt.Errorf("PATH is required (provide positionally or via -path): %w", ErrUsage)
	}
	return path, nil
}

// MergeServerResponseInto copies fields from `resource.Data` (if any) into
// `data` and then re-applies `markers` so caller-set flags like
// {"created": true, "path": "..."} always win over any same-named field
// the server happens to include. The contract: the marker keys are
// guaranteed in the rendered envelope so agents can branch on them.
func MergeServerResponseInto(data map[string]any, resourceData map[string]any, markers map[string]any) {
	if resourceData != nil {
		maps.Copy(data, resourceData)
	}
	maps.Copy(data, markers)
}
