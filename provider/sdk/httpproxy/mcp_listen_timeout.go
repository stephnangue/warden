package httpproxy

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

// listenMethod is the MCP method that opens an open-ended notification
// stream. Comparison is case-insensitive to match how the policy matcher
// reads a method off the wire.
const listenMethod = "subscriptions/listen"

// ListenTimeoutKey is the config field and state key holding the per-mount
// deadline for subscriptions/listen calls.
const ListenTimeoutKey = "listen_timeout"

// DefaultListenTimeout caps one subscriptions/listen stream. A listen stream
// is meant to stay open for as long as the client wants notifications, so
// this sits far above any unary shape. The value preserves the streaming
// ceiling MCP mounts had when the mount timeout was the only knob.
const DefaultListenTimeout = 10 * time.Minute

// ListenTimeoutField returns the FieldSchema for the listen_timeout config
// field. MCP providers spread this into their config fields under
// ListenTimeoutKey.
func ListenTimeoutField() *framework.FieldSchema {
	return &framework.FieldSchema{
		Type: framework.TypeDurationSecond,
		Description: "Deadline for a subscriptions/listen stream (default: 10m). " +
			"Every other call answers to timeout instead, so a long-running " +
			"tool call is not covered by this value.",
		Default: DefaultListenTimeout.String(),
	}
}

// ParseListenTimeout reads listen_timeout from a persisted or mount config
// map, in either the string form it is written back as or the numeric
// seconds form a config write produces. Falls back to the default when the
// key is absent or does not yield a positive duration.
func ParseListenTimeout(conf map[string]any) time.Duration {
	v, ok := conf[ListenTimeoutKey]
	if !ok {
		return DefaultListenTimeout
	}
	switch t := v.(type) {
	case time.Duration:
		if t > 0 {
			return t
		}
	case string:
		if d, err := time.ParseDuration(t); err == nil && d > 0 {
			return d
		}
	case int:
		if t > 0 {
			return time.Duration(t) * time.Second
		}
	case int64:
		if t > 0 {
			return time.Duration(t) * time.Second
		}
	case float64:
		if t > 0 {
			return time.Duration(t) * time.Second
		}
	}
	return DefaultListenTimeout
}

// ReadListenTimeout returns the listen_timeout held in a backend's extra
// state, applying the default when unset. Providers call this from
// ProviderSpec.OnConfigRead — where the string form is what gets persisted
// and shown — and from their SelectTimeout hook.
func ReadListenTimeout(state map[string]any) time.Duration {
	d, _ := state[ListenTimeoutKey].(time.Duration)
	if d <= 0 {
		return DefaultListenTimeout
	}
	return d
}

// WriteListenTimeout validates an incoming listen_timeout from a config
// write and stores the accepted value in state. State is left untouched
// when the value is rejected, and when the field is absent from the write
// payload this is a no-op. Providers call this from
// ProviderSpec.OnConfigWrite.
func WriteListenTimeout(d *framework.FieldData, state map[string]any) error {
	val, ok := d.GetOk(ListenTimeoutKey)
	if !ok {
		return nil
	}
	secs, ok := val.(int)
	if !ok {
		return fmt.Errorf("%s must be a duration", ListenTimeoutKey)
	}
	if secs <= 0 {
		return fmt.Errorf("%s must be greater than 0", ListenTimeoutKey)
	}
	state[ListenTimeoutKey] = time.Duration(secs) * time.Second
	return nil
}

// InitializeListenTimeout loads listen_timeout from persisted config into
// state. Providers call this from ProviderSpec.OnInitialize.
func InitializeListenTimeout(config map[string]any, state map[string]any) {
	state[ListenTimeoutKey] = ParseListenTimeout(config)
}

// OpensNotificationStream reports whether req opens an open-ended stream of
// server notifications, in either protocol era.
//
// Modern era: a single subscriptions/listen call. The method comes off the
// MCP descriptor core attached before the backend handler ran, so it is known
// without touching the body again. Everything else on that side is false, and
// deliberately: a batch cannot be characterised by one of its elements, and a
// nil descriptor means this request was never parsed as MCP.
//
// Legacy era: the standalone SSE GET. It is subscriptions/listen's
// predecessor and equally open-ended, but it carries no body, so it reaches
// the backend as the empty sentinel with no method to read — the verb is the
// only thing that identifies it. Without this branch a legacy notification
// stream would answer to the unary ceiling, which is far below what it needs.
func OpensNotificationStream(req *logical.Request) bool {
	if req == nil {
		return false
	}
	if req.HTTPRequest != nil && req.HTTPRequest.Method == http.MethodGet {
		return true
	}
	if req.MCPDescriptor == nil {
		return false
	}
	calls := req.MCPDescriptor.Calls
	if len(calls) != 1 {
		return false
	}
	return strings.EqualFold(calls[0].Method, listenMethod)
}

// SelectListenTimeout is the ProviderSpec.SelectTimeout implementation MCP
// providers share: the mount's listen_timeout for a request that opens a
// notification stream, and zero — meaning "keep the mount timeout" — for
// every other shape.
//
// The split is the point. A subscription is open-ended and needs hours; a
// tools/call is not, and giving the whole mount the subscription's ceiling
// would let any hung call hold its goroutine and both connections for just
// as long.
func SelectListenTimeout(req *logical.Request, state map[string]any) time.Duration {
	if !OpensNotificationStream(req) {
		return 0
	}
	return ReadListenTimeout(state)
}
