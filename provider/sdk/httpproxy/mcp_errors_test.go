package httpproxy

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/hashicorp/go-multierror"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Stand-ins for core's typed MCP errors, which this package cannot import.
type fakePolicyRefusal struct{ desc string }

func (e *fakePolicyRefusal) Error() string              { return "permission denied" }
func (e *fakePolicyRefusal) MCPDenyDescription() string { return e.desc }

type fakeHeaderRefusal struct{}

func (e *fakeHeaderRefusal) Error() string      { return "permission denied" }
func (e *fakeHeaderRefusal) MCPHeaderMismatch() {}

// mcpCallRequest builds a POST whose logical request carries a descriptor for
// one call with the given raw id.
func mcpCallRequest(rawID string) *logical.Request {
	return &logical.Request{
		HTTPRequest: httptest.NewRequest(http.MethodPost, "/mcp/gateway/", strings.NewReader(`{}`)),
		MCPDescriptor: &logical.MCPRequestDescriptor{Calls: []logical.MCPCall{{
			Method:    "tools/call",
			RawID:     json.RawMessage(rawID),
			IDPresent: true,
		}}},
	}
}

func decodeMCPError(t *testing.T, body []byte) mcpErrorResponse {
	t.Helper()
	var got mcpErrorResponse
	require.NoError(t, json.Unmarshal(body, &got))
	assert.Equal(t, "2.0", got.JSONRPC)
	return got
}

// The point of rendering at all: a client must read the refusal as a JSON-RPC
// response to its call, not a transport failure. The Go SDK's client decides
// that with this very decoder — a body it decodes as a response with an error
// fails the one call, anything else closes the session.
func TestRenderMCPGatewayError_ClientReadsItAsTheCallsAnswer(t *testing.T) {
	resp := RenderMCPGatewayError(WithMCPCallID(mcpCallRequest(`7`)), &logical.GatewayFailure{
		Class:  logical.GatewayFailureDenied,
		Status: http.StatusForbidden,
		Err:    multierror.Append(nil, &fakePolicyRefusal{desc: "Tool 'close_account' not allowed."}),
	})
	require.NotNil(t, resp)

	msg, err := jsonrpc.DecodeMessage(resp.Body)
	require.NoError(t, err)
	r, ok := msg.(*jsonrpc.Response)
	require.True(t, ok, "decoded as a response")
	require.Error(t, r.Error)
	want, _ := jsonrpc.MakeID(float64(7))
	assert.Equal(t, want, r.ID)

	// The SDKs give -32000 to -32005 meanings of their own; the Go SDK reads
	// -32003 as "client is closing" and tears the session down over it.
	var wire *jsonrpc.Error
	require.ErrorAs(t, r.Error, &wire)
	assert.False(t, wire.Code <= -32000 && wire.Code >= -32005, "code %d is one an SDK uses", wire.Code)
}

func TestRenderMCPGatewayError_PolicyRefusal(t *testing.T) {
	const desc = "Tool 'close_account' not allowed."
	resp := RenderMCPGatewayError(WithMCPCallID(mcpCallRequest(`"call-1"`)), &logical.GatewayFailure{
		Class:     logical.GatewayFailureDenied,
		Status:    http.StatusForbidden,
		Err:       multierror.Append(nil, &fakePolicyRefusal{desc: desc}),
		RequestID: "req-9",
	})
	require.NotNil(t, resp)

	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "the status is Warden's decision and is kept")
	assert.Equal(t, "application/json", resp.Headers.Get("Content-Type"))
	assert.Equal(t, `Bearer error="insufficient_permissions", error_description="`+desc+`"`,
		resp.Headers.Get("WWW-Authenticate"))

	got := decodeMCPError(t, resp.Body)
	assert.JSONEq(t, `"call-1"`, string(got.ID), "a string id is echoed verbatim")
	assert.Equal(t, jsonRPCCodeRefused, got.Error.Code)
	assert.Equal(t, "Warden: "+desc, got.Error.Message)
	require.NotNil(t, got.Error.Data)
	assert.Equal(t, mcpRefusalData{
		Error:            "insufficient_permissions",
		ErrorDescription: desc,
		RequestID:        "req-9",
	}, *got.Error.Data)
}

// A header mismatch shares the policy refusal's 403 status on the way in, and
// is answered with the spec's own status and code instead.
func TestRenderMCPGatewayError_HeaderMismatch(t *testing.T) {
	resp := RenderMCPGatewayError(WithMCPCallID(mcpCallRequest(`3`)), &logical.GatewayFailure{
		Class:  logical.GatewayFailureDenied,
		Status: http.StatusForbidden,
		Err:    multierror.Append(nil, &fakeHeaderRefusal{}),
	})
	require.NotNil(t, resp)

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Empty(t, resp.Headers.Get("WWW-Authenticate"), "not an authorization decision")
	got := decodeMCPError(t, resp.Body)
	assert.JSONEq(t, `3`, string(got.ID))
	assert.Equal(t, jsonRPCCodeHeaderMismatch, got.Error.Code)
	assert.Equal(t, "MCP transport headers do not match the request body", got.Error.Message)
	assert.Nil(t, got.Error.Data)
}

func TestRenderMCPGatewayError_OtherFailuresByStatus(t *testing.T) {
	cases := []struct {
		name   string
		status int
		code   int
	}{
		{"unauthenticated", http.StatusUnauthorized, jsonRPCCodeRefused},
		{"forbidden without an mcp decision", http.StatusForbidden, jsonRPCCodeRefused},
		{"bad request", http.StatusBadRequest, jsonRPCCodeInvalidRequest},
		{"rate limited", http.StatusTooManyRequests, jsonRPCCodeInvalidRequest},
		{"unavailable", http.StatusServiceUnavailable, jsonRPCCodeInternalError},
		{"upstream unreachable", http.StatusBadGateway, jsonRPCCodeInternalError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := RenderMCPGatewayError(WithMCPCallID(mcpCallRequest(`1`)), &logical.GatewayFailure{
				Status: tc.status,
				Err:    errors.New("something failed"),
			})
			require.NotNil(t, resp)
			assert.Equal(t, tc.status, resp.StatusCode)
			assert.Empty(t, resp.Headers.Get("WWW-Authenticate"),
				"a challenge core attached is kept by core, not invented here")
			got := decodeMCPError(t, resp.Body)
			assert.Equal(t, tc.code, got.Error.Code)
			assert.Equal(t, "Warden: something failed", got.Error.Message)
		})
	}
}

// Without a single call to answer, the id is null — all JSON-RPC allows.
func TestRenderMCPGatewayError_NullIDWithoutASingleCall(t *testing.T) {
	failure := &logical.GatewayFailure{Status: http.StatusForbidden, Err: errors.New("permission denied")}
	cases := map[string]*logical.Request{
		"no descriptor": {HTTPRequest: httptest.NewRequest(http.MethodPost, "/", nil)},
		"notification": {
			HTTPRequest:   httptest.NewRequest(http.MethodPost, "/", nil),
			MCPDescriptor: &logical.MCPRequestDescriptor{Calls: []logical.MCPCall{{Method: "notifications/initialized"}}},
		},
		"batch of one": {
			HTTPRequest: httptest.NewRequest(http.MethodPost, "/", nil),
			MCPDescriptor: &logical.MCPRequestDescriptor{IsBatch: true, Calls: []logical.MCPCall{
				{RawID: json.RawMessage(`1`), IDPresent: true},
			}},
		},
		"batch of two": {
			HTTPRequest: httptest.NewRequest(http.MethodPost, "/", nil),
			MCPDescriptor: &logical.MCPRequestDescriptor{IsBatch: true, Calls: []logical.MCPCall{
				{RawID: json.RawMessage(`1`), IDPresent: true},
				{RawID: json.RawMessage(`2`), IDPresent: true},
			}},
		},
		"unparsed body": {
			HTTPRequest: httptest.NewRequest(http.MethodPost, "/", nil),
			MCPDescriptor: &logical.MCPRequestDescriptor{
				ParseErr: &logical.MCPParseError{Kind: logical.MCPParseKindMalformedJSONRPC},
			},
		},
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			resp := RenderMCPGatewayError(WithMCPCallID(req), failure)
			require.NotNil(t, resp)
			got := decodeMCPError(t, resp.Body)
			assert.Equal(t, "null", string(got.ID))
		})
	}
}

// GET and DELETE carry no JSON-RPC, so there is no call to answer.
func TestRenderMCPGatewayError_DeclinesNonPost(t *testing.T) {
	failure := &logical.GatewayFailure{Status: http.StatusForbidden, Err: errors.New("permission denied")}
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		assert.Nil(t, RenderMCPGatewayError(httptest.NewRequest(method, "/", nil), failure), method)
	}
	assert.Nil(t, RenderMCPGatewayError(nil, failure))
}

// WithMCPCallID allocates a new request only when there is an id to carry.
func TestWithMCPCallID(t *testing.T) {
	plain := &logical.Request{HTTPRequest: httptest.NewRequest(http.MethodPost, "/", nil)}
	assert.Same(t, plain.HTTPRequest, WithMCPCallID(plain))
	assert.Nil(t, WithMCPCallID(&logical.Request{}))

	req := mcpCallRequest(`5`)
	r := WithMCPCallID(req)
	assert.NotSame(t, req.HTTPRequest, r)
	assert.Equal(t, json.RawMessage(`5`), r.Context().Value(mcpCallIDCtxKey))
}

// Core hands the renderer the logical request; the backend must pass the id on.
func TestProxyBackend_RenderGatewayError_EchoesTheCallID(t *testing.T) {
	spec := testSpec()
	spec.RenderGatewayError = RenderMCPGatewayError
	pb := setupBackend(t, spec).(*proxyBackend)

	resp := pb.RenderGatewayError(mcpCallRequest(`11`), &logical.GatewayFailure{
		Status: http.StatusForbidden,
		Err:    &fakePolicyRefusal{desc: "Tool 'x' not allowed."},
	})
	require.NotNil(t, resp)
	assert.JSONEq(t, `11`, string(decodeMCPError(t, resp.Body).ID))
}

// The proxy's own failures have only the HTTP request; handleGateway puts the
// id on it before proxying.
func TestHandleGateway_ProxyFailureEchoesTheCallID(t *testing.T) {
	gone := httptest.NewServer(http.NotFoundHandler())
	gone.Close()

	spec := testSpec()
	spec.RenderGatewayError = RenderMCPGatewayError
	pb := setupBackend(t, spec).(*proxyBackend)
	pb.providerURL = gone.URL

	req := mcpCallRequest(`12`)
	req.HTTPRequest.URL, _ = url.Parse(gone.URL + "/test/gateway/")
	rec := httptest.NewRecorder()
	req.ResponseWriter = rec
	req.Credential = &credential.Credential{Type: credential.TypeAPIKey, Data: map[string]string{"api_key": "sk-test"}}
	pb.handleGateway(context.Background(), req)

	assert.Equal(t, http.StatusBadGateway, rec.Code)
	got := decodeMCPError(t, rec.Body.Bytes())
	assert.JSONEq(t, `12`, string(got.ID))
	assert.Equal(t, jsonRPCCodeInternalError, got.Error.Code)
	assert.Equal(t, "Warden: the upstream could not be reached", got.Error.Message)
}
