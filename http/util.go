package http

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/stephnangue/warden/core"
	"github.com/stephnangue/warden/logical"
)

// ErrorResponse represents a JSON error response
type ErrorResponse struct {
	Errors []string `json:"errors"`
}

// respondError writes an error response with the given status code and message.
func respondError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	resp := &ErrorResponse{
		Errors: []string{message},
	}

	json.NewEncoder(w).Encode(resp)
}

// respondOk writes a successful JSON response with status 200.
func respondOk(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}

// mcpDenyResponse is the OAuth-conventional JSON body shape returned by
// respondMCPDeny. Matches the MCP Python reference SDK's deny shape so
// any RFC 6750-aware client surfaces it the same way it would surface
// an OAuth insufficient-permissions error from any other MCP server.
type mcpDenyResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// respondMCPDeny renders an MCP policy denial as an HTTP 403 with the
// RFC 6750-shaped WWW-Authenticate header and an OAuth-conventional
// JSON body. Body and header carry the same error_description text so
// SDKs that surface one or the other see identical messages.
//
// The MCP spec handles permission denial at the HTTP layer (not in-band
// JSON-RPC), so this body is NOT a JSON-RPC envelope — no jsonrpc
// field, no error.code, no id. The error value is
// "insufficient_permissions" (Cloudflare-style RFC 6750 extension) to
// distinguish from "insufficient_scope" which implies an OAuth scope
// the client could go fetch — this isn't an OAuth scope mismatch,
// it's a gateway policy decision.
//
// Description templates per RuleType live in core/policy_mcp.go's
// BuildMCPDenyDescription so the wire shape and the audit JSON tags
// stay in lockstep.
// jsonRPCCodeHeaderMismatch is the spec's error code for a request whose
// transport headers contradict its body.
const jsonRPCCodeHeaderMismatch = -32020

// jsonRPCError is a JSON-RPC 2.0 error response. Unlike a policy denial,
// which the MCP spec handles at the HTTP layer, a header mismatch is a
// protocol-level fault and gets a real JSON-RPC envelope with the request's
// id echoed back.
type jsonRPCError struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Error   jsonRPCErrorObj `json:"error"`
}

type jsonRPCErrorObj struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// respondMCPHeaderMismatch renders a transport-header refusal as HTTP 400
// with a JSON-RPC -32020 body.
//
// Returning the error the modern spec defines, rather than the 403 a policy
// denial gets, is what stops a dual-era client reading the refusal as "not
// permitted" and answering by downgrading to initialize. The message names
// no header and no value: the client already knows what it sent, and an
// attacker should not be handed a probe for which half of the check fired.
//
// The id is echoed verbatim from the request. A body with no id is a
// notification, which by JSON-RPC takes no response at all — but one that
// reaches here failed validation, so the status still carries the refusal
// and the id renders as null.
func respondMCPHeaderMismatch(w http.ResponseWriter, rawID json.RawMessage, idPresent bool) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)

	id := json.RawMessage("null")
	if idPresent && len(rawID) > 0 {
		id = rawID
	}
	_ = json.NewEncoder(w).Encode(&jsonRPCError{
		JSONRPC: "2.0",
		ID:      id,
		Error: jsonRPCErrorObj{
			Code:    jsonRPCCodeHeaderMismatch,
			Message: "MCP transport headers do not match the request body",
		},
	})
}

func respondMCPDeny(w http.ResponseWriter, status int, d *logical.MCPDecision) {
	desc := core.BuildMCPDenyDescription(d)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate",
		fmt.Sprintf(`Bearer error="insufficient_permissions", error_description=%q`, desc))
	w.WriteHeader(status)

	resp := &mcpDenyResponse{
		Error:            "insufficient_permissions",
		ErrorDescription: desc,
	}
	json.NewEncoder(w).Encode(resp)
}
