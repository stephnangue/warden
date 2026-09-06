package httpproxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

// listenReq builds a POST carrying the given JSON-RPC methods, which is the
// only shape that produces parsed calls.
func listenReq(methods ...string) *logical.Request {
	calls := make([]logical.MCPCall, len(methods))
	for i, m := range methods {
		calls[i] = logical.MCPCall{Method: m, BatchIndex: i}
	}
	return verbReq(http.MethodPost, &logical.MCPRequestDescriptor{Calls: calls})
}

func verbReq(method string, desc *logical.MCPRequestDescriptor) *logical.Request {
	return &logical.Request{
		HTTPRequest:   httptest.NewRequest(method, "/v1/mcp/gateway/", nil),
		MCPDescriptor: desc,
	}
}

func TestOpensNotificationStream(t *testing.T) {
	tests := []struct {
		name string
		req  *logical.Request
		want bool
	}{
		{"single listen", listenReq("subscriptions/listen"), true},
		{
			// The matcher lowercases a method before comparing, so the
			// deadline picker must agree with it rather than admit a shape
			// the gate would have treated as a listen.
			name: "listen, odd casing",
			req:  listenReq("Subscriptions/Listen"),
			want: true,
		},
		{"tools/call", listenReq("tools/call"), false},
		{
			// A batch cannot be characterised by one of its elements: the
			// unary ceiling is the safe reading.
			name: "batch containing a listen",
			req:  listenReq("tools/call", "subscriptions/listen"),
			want: false,
		},
		{"batch of one listen", listenReq("subscriptions/listen", "subscriptions/listen"), false},
		{
			// A POST the backend declined to enforce on — a non-JSON
			// Content-Type. No method to read, so no exemption.
			name: "empty sentinel on a POST",
			req:  verbReq(http.MethodPost, &logical.MCPRequestDescriptor{}),
			want: false,
		},
		{
			// The legacy standalone SSE stream. It carries no body, so it
			// arrives as the empty sentinel and the verb is all there is to
			// go on — but it is as open-ended as subscriptions/listen, and
			// capping it at the unary ceiling would sever the legacy era's
			// only notification channel.
			name: "legacy SSE GET",
			req:  verbReq(http.MethodGet, &logical.MCPRequestDescriptor{}),
			want: true,
		},
		{
			// DELETE closes a session. It shares the sentinel with the GET
			// but is a one-shot, so it keeps the unary ceiling.
			name: "session-closing DELETE",
			req:  verbReq(http.MethodDelete, &logical.MCPRequestDescriptor{}),
			want: false,
		},
		{
			name: "parse error",
			req: &logical.Request{MCPDescriptor: &logical.MCPRequestDescriptor{
				ParseErr: &logical.MCPParseError{Kind: logical.MCPParseKindMalformedJSONRPC},
			}},
			want: false,
		},
		{"no descriptor — every non-MCP provider", &logical.Request{}, false},
		{"nil request", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, OpensNotificationStream(tt.req))
		})
	}
}

// SelectListenTimeout returning 0 is what keeps the mount timeout in force;
// only a listen may lift it.
func TestSelectListenTimeout(t *testing.T) {
	state := map[string]any{ListenTimeoutKey: 2 * time.Hour}

	assert.Equal(t, 2*time.Hour, SelectListenTimeout(listenReq("subscriptions/listen"), state))
	assert.Zero(t, SelectListenTimeout(listenReq("tools/call"), state))
	assert.Zero(t, SelectListenTimeout(listenReq("tools/call", "subscriptions/listen"), state))
	assert.Zero(t, SelectListenTimeout(&logical.Request{}, state))

	// The legacy SSE GET is a notification stream too.
	assert.Equal(t, 2*time.Hour, SelectListenTimeout(verbReq(http.MethodGet, nil), state))
	assert.Zero(t, SelectListenTimeout(verbReq(http.MethodDelete, nil), state))

	// An unconfigured mount still gets the default rather than falling back
	// to the unary ceiling.
	assert.Equal(t, DefaultListenTimeout, SelectListenTimeout(listenReq("subscriptions/listen"), map[string]any{}))
}

func TestParseListenTimeout(t *testing.T) {
	tests := []struct {
		name string
		conf map[string]any
		want time.Duration
	}{
		{"absent", map[string]any{}, DefaultListenTimeout},
		{"string, as persisted", map[string]any{ListenTimeoutKey: "1h30m"}, 90 * time.Minute},
		{"seconds, as a config write yields", map[string]any{ListenTimeoutKey: 45}, 45 * time.Second},
		{"seconds as float, as JSON storage yields", map[string]any{ListenTimeoutKey: float64(45)}, 45 * time.Second},
		{"duration", map[string]any{ListenTimeoutKey: 3 * time.Hour}, 3 * time.Hour},
		{"unparseable string", map[string]any{ListenTimeoutKey: "soon"}, DefaultListenTimeout},
		{"zero", map[string]any{ListenTimeoutKey: 0}, DefaultListenTimeout},
		{"negative", map[string]any{ListenTimeoutKey: "-5m"}, DefaultListenTimeout},
		{"wrong type", map[string]any{ListenTimeoutKey: true}, DefaultListenTimeout},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ParseListenTimeout(tt.conf))
		})
	}
}

func TestReadListenTimeout(t *testing.T) {
	assert.Equal(t, DefaultListenTimeout, ReadListenTimeout(map[string]any{}))
	assert.Equal(t, DefaultListenTimeout, ReadListenTimeout(map[string]any{ListenTimeoutKey: time.Duration(0)}))
	assert.Equal(t, 5*time.Minute, ReadListenTimeout(map[string]any{ListenTimeoutKey: 5 * time.Minute}))
}

func TestWriteListenTimeout(t *testing.T) {
	schema := map[string]*framework.FieldSchema{ListenTimeoutKey: ListenTimeoutField()}

	fieldData := func(raw map[string]any) *framework.FieldData {
		return &framework.FieldData{Raw: raw, Schema: schema}
	}

	t.Run("absent leaves state alone", func(t *testing.T) {
		state := map[string]any{}
		require.NoError(t, WriteListenTimeout(fieldData(map[string]any{}), state))
		assert.Empty(t, state)
	})

	t.Run("accepted value is stored as a duration", func(t *testing.T) {
		state := map[string]any{}
		require.NoError(t, WriteListenTimeout(fieldData(map[string]any{ListenTimeoutKey: "1h"}), state))
		assert.Equal(t, time.Hour, state[ListenTimeoutKey])
	})

	t.Run("non-positive is rejected and state is untouched", func(t *testing.T) {
		state := map[string]any{ListenTimeoutKey: time.Hour}
		err := WriteListenTimeout(fieldData(map[string]any{ListenTimeoutKey: "0s"}), state)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "greater than 0")
		assert.Equal(t, time.Hour, state[ListenTimeoutKey], "a rejected write must not half-apply")
	})
}

func TestInitializeListenTimeout(t *testing.T) {
	state := map[string]any{}
	InitializeListenTimeout(map[string]any{ListenTimeoutKey: "15m"}, state)
	assert.Equal(t, 15*time.Minute, state[ListenTimeoutKey])

	// A mount persisted before the field existed still comes up with a
	// working ceiling.
	state = map[string]any{}
	InitializeListenTimeout(map[string]any{}, state)
	assert.Equal(t, DefaultListenTimeout, state[ListenTimeoutKey])
}
