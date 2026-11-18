package audit

import (
	"context"
	"errors"
)

// JSONFormat implements the Format interface for JSON output.
//
// Nothing of it changes once NewJSONFormat returns: entries are formatted
// from any number of goroutines at once.
type JSONFormat struct {
	prefix string

	// redaction is the salt and omit paths, compiled.
	redaction redaction

	// The paths as given, kept until every option is applied: a salt path
	// counts only if the format can salt, whatever the order of the options.
	saltFields []string
	omitFields []string
}

// NewJSONFormat creates a new JSON format
func NewJSONFormat(opts ...JSONFormatOption) *JSONFormat {
	f := &JSONFormat{}

	for _, opt := range opts {
		opt(f)
	}

	// A path that names no field is skipped, and the others still apply.
	// Paths are checked when the device is created.
	if f.redaction.canSalt() {
		for _, path := range f.saltFields {
			_ = f.redaction.compile(true, path)
		}
	}
	for _, path := range f.omitFields {
		_ = f.redaction.compile(false, path)
	}
	f.saltFields, f.omitFields = nil, nil

	return f
}

// JSONFormatOption is a functional option for JSONFormat
type JSONFormatOption func(*JSONFormat)

// WithPrefix sets a prefix for each log line
func WithPrefix(prefix string) JSONFormatOption {
	return func(f *JSONFormat) {
		f.prefix = prefix
	}
}

// WithHMACer salts sensitive data under the key of h. It is how a device
// salts: values go from the entry to the log without an allocation.
func WithHMACer(h *HMACer) JSONFormatOption {
	return func(f *JSONFormat) {
		f.redaction.hmac = h
	}
}

// WithSaltFunc sets a salt function for sensitive data. A value it fails to
// salt is written empty, not in clear. WithHMACer takes precedence.
func WithSaltFunc(fn SaltFunc) JSONFormatOption {
	return func(f *JSONFormat) {
		f.redaction.saltFn = fn
	}
}

// WithOmitFields sets fields to omit from output
func WithOmitFields(fields []string) JSONFormatOption {
	return func(f *JSONFormat) {
		f.omitFields = fields
	}
}

// WithSaltFields sets fields to salt in the output
func WithSaltFields(fields []string) JSONFormatOption {
	return func(f *JSONFormat) {
		f.saltFields = fields
	}
}

// AppendRequest appends entry, formatted as a request, to dst.
func (f *JSONFormat) AppendRequest(ctx context.Context, dst []byte, entry *LogEntry) ([]byte, error) {
	return f.append(ctx, dst, entry, EntryTypeRequest)
}

// AppendResponse appends entry, formatted as a response, to dst.
func (f *JSONFormat) AppendResponse(ctx context.Context, dst []byte, entry *LogEntry) ([]byte, error) {
	return f.append(ctx, dst, entry, EntryTypeResponse)
}

// FormatRequest formats a request entry as JSON
func (f *JSONFormat) FormatRequest(ctx context.Context, entry *LogEntry) ([]byte, error) {
	return f.AppendRequest(ctx, nil, entry)
}

// FormatResponse formats a response entry as JSON
func (f *JSONFormat) FormatResponse(ctx context.Context, entry *LogEntry) ([]byte, error) {
	return f.AppendResponse(ctx, nil, entry)
}

// append appends entry to dst after the prefix, as an entry of the given
// type, with the fields the format salts salted and those it omits left out.
// The entry is read and never written: it is the one every device is handed.
// What append returns with an error is not an entry.
func (f *JSONFormat) append(ctx context.Context, dst []byte, entry *LogEntry, entryType EntryType) ([]byte, error) {
	enc := jsonEncoder{buf: append(dst, f.prefix...), red: &f.redaction, ctx: ctx}
	if err := enc.entry(entry, string(entryType)); err != nil {
		return dst, err
	}
	return enc.buf, nil
}

// Name returns the format name
func (f *JSONFormat) Name() string {
	return "json"
}

var (
	// errUnknownFieldPath: the path names no field of an audit entry.
	errUnknownFieldPath = errors.New("matches no audit field")
	// errNotSaltable: the path names a group of fields, which only omission
	// takes whole.
	errNotSaltable = errors.New("names a group of fields: salt the fields inside it")
	// errNeverLogged: the path names a request or response header or body,
	// which no entry records.
	errNeverLogged = errors.New("request and response headers and bodies are not fields of an audit entry")
)

// checkFieldPath reports whether path names a field that a salt path (salt)
// or an omit path can act on. It compiles the path as a format does, so the
// paths a format applies and the paths accepted here cannot drift apart.
func checkFieldPath(salt bool, path string) error {
	var scratch redaction
	return scratch.compile(salt, path)
}

// leaf refuses segments after a field that has none below it.
func leaf(rest []string) error {
	if len(rest) > 0 {
		return errUnknownFieldPath
	}
	return nil
}

// mapKey reads the segments after a map field: none names the whole map, one
// names a key.
// An empty key (a trailing dot) names nothing: it would match no value and
// leave the operator believing one salted.
func mapKey(rest []string) (key string, whole bool, err error) {
	switch {
	case len(rest) == 0:
		return "", true, nil
	case len(rest) == 1 && rest[0] != "":
		return rest[0], false, nil
	}
	return "", false, errUnknownFieldPath
}

// neverLogged reports whether name is a request or response field that used
// to record headers or a body. Omitting one is accepted and does nothing, so
// configurations written for earlier releases stay valid.
func neverLogged(name string) bool {
	return name == "headers" || name == "data"
}
