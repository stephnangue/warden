package httpproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/stephnangue/warden/logical"
)

// JSON-RPC error codes the MCP renderer answers with.
const (
	jsonRPCCodeInvalidRequest = -32600
	jsonRPCCodeInternalError  = -32603
	jsonRPCCodeHeaderMismatch = -32020
	// jsonRPCCodeRefused is Warden's own: the gateway refused the call, by
	// policy or for want of a valid identity. Retrying it unchanged will fail
	// the same way.
	//
	// It keeps clear of every code a client already gives a meaning: the MCP
	// SDKs use -32000 to -32005 internally (the Go SDK matches errors by code,
	// and reads -32003 as its own "client is closing", so a refusal under it
	// tears the session down), and the spec has taken -32002, -32020 to
	// -32022 and -32042.
	jsonRPCCodeRefused = -32090
)

type mcpCallIDCtxKeyT struct{}

var mcpCallIDCtxKey = mcpCallIDCtxKeyT{}

// mcpCallID returns the id of the request's JSON-RPC call when there is
// exactly one to answer: not a batch, which takes an array in reply, and not a
// notification, which has no id.
func mcpCallID(req *logical.Request) (json.RawMessage, bool) {
	d := req.MCPDescriptor
	if d == nil || d.IsBatch || len(d.Calls) != 1 {
		return nil, false
	}
	c := d.Calls[0]
	if !c.IDPresent || len(c.RawID) == 0 {
		return nil, false
	}
	return c.RawID, true
}

// WithMCPCallID returns req's HTTP request carrying the id of its JSON-RPC
// call, for RenderMCPGatewayError to echo. A request with no single call to
// answer is returned as it is.
//
// The id goes on the HTTP request because that is all a gateway error renderer
// is handed: the proxy's own failures (502, 504) have nothing else.
func WithMCPCallID(req *logical.Request) *http.Request {
	r := req.HTTPRequest
	if r == nil {
		return nil
	}
	if id, ok := mcpCallID(req); ok {
		return r.WithContext(context.WithValue(r.Context(), mcpCallIDCtxKey, id))
	}
	return r
}

type mcpErrorResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Error   mcpErrorObject  `json:"error"`
}

type mcpErrorObject struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    *mcpRefusalData `json:"data,omitempty"`
}

// mcpRefusalData repeats the OAuth-shaped fields Warden answered a refusal
// with before it was a JSON-RPC error, so a client that read them still can.
type mcpRefusalData struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	RequestID        string `json:"request_id,omitempty"`
}

// RenderMCPGatewayError answers a JSON-RPC call Warden failed itself with a
// JSON-RPC error that echoes the call's id, so an MCP client fails that one
// call and keeps its session. A body that is not a JSON-RPC response is a
// transport failure to a client, and the Go SDK, for one, closes the whole
// session over it — every later call fails with "client is closing".
//
// The HTTP status is the failure's own and is not changed, with one exception:
// a header mismatch is answered 400 with -32020, as the spec defines it. A
// policy refusal keeps its RFC 6750 WWW-Authenticate challenge.
//
// Only POST is rendered, the one verb that carries JSON-RPC; the GET and
// DELETE of the legacy transport keep Warden's generic body. A call whose id
// is unknown — a batch, a notification, or a body that never parsed — is
// answered with a null id, which is the most JSON-RPC allows.
func RenderMCPGatewayError(r *http.Request, f *logical.GatewayFailure) *logical.Response {
	if r == nil || r.Method != http.MethodPost {
		return nil
	}
	id, _ := r.Context().Value(mcpCallIDCtxKey).(json.RawMessage)
	if len(id) == 0 {
		id = json.RawMessage("null")
	}

	status := f.Status
	headers := http.Header{"Content-Type": []string{"application/json"}}
	obj := mcpErrorObject{Message: WardenErrorMessage(f.Err)}

	var headerRefusal logical.MCPHeaderRefusal
	var policyRefusal logical.MCPPolicyRefusal
	switch {
	case errors.As(f.Err, &headerRefusal):
		// Names no header and no value: the client knows what it sent, and an
		// attacker should not learn which half of the check fired.
		status = http.StatusBadRequest
		obj.Code = jsonRPCCodeHeaderMismatch
		obj.Message = "MCP transport headers do not match the request body"
	case errors.As(f.Err, &policyRefusal):
		desc := policyRefusal.MCPDenyDescription()
		headers.Set("WWW-Authenticate",
			fmt.Sprintf(`Bearer error="insufficient_permissions", error_description=%q`, desc))
		obj.Code = jsonRPCCodeRefused
		obj.Message = "Warden: " + desc
		obj.Data = &mcpRefusalData{
			Error:            "insufficient_permissions",
			ErrorDescription: desc,
			RequestID:        f.RequestID,
		}
	case f.Status == http.StatusUnauthorized || f.Status == http.StatusForbidden:
		obj.Code = jsonRPCCodeRefused
	case f.Status >= 400 && f.Status < 500:
		obj.Code = jsonRPCCodeInvalidRequest
	default:
		obj.Code = jsonRPCCodeInternalError
	}

	body, err := json.Marshal(&mcpErrorResponse{JSONRPC: "2.0", ID: id, Error: obj})
	if err != nil {
		return nil
	}
	return &logical.Response{StatusCode: status, Headers: headers, Body: body}
}
