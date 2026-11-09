package anthropic

import (
	"encoding/json"
	"net/http"

	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/sdk/httpproxy"
)

// Anthropic's error types, as its API documents them, for the statuses Warden
// itself answers a gateway request with. The SDKs classify an error by its HTTP
// status; type is what they surface to the caller. Anthropic's error has no code
// field, so nothing says "Warden" but the message's prefix — which is the point
// of the prefix.
//
// There is deliberately no rate_limit_error: Warden never answers a gateway
// request 429 itself. Anthropic's own 429s stream back untouched, and a 429 from
// its token endpoint during a mint is answered 503 (see CredentialIssueError).
// Nor is there a not_found_error: a gateway path with no mount behind it has no
// backend to render its 404.
const (
	anthropicTypeInvalidRequest = "invalid_request_error"
	anthropicTypeAuthentication = "authentication_error"
	anthropicTypePermission     = "permission_error"
	anthropicTypeTooLarge       = "request_too_large"
	anthropicTypeAPI            = "api_error"
	anthropicTypeTimeout        = "timeout_error"
)

// anthropicErrorBody is Anthropic's error envelope.
type anthropicErrorBody struct {
	Type      string         `json:"type"`
	Error     anthropicError `json:"error"`
	RequestID string         `json:"request_id,omitempty"`
}

type anthropicError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

// renderAnthropicError answers a gateway failure Warden raised itself in
// Anthropic's error shape, so an Anthropic SDK surfaces Warden's reason instead
// of failing to parse Warden's generic body. It is the same whichever channel
// the agent authenticated on. The status is Warden's, unchanged: it already says
// whether a retry can help, which is what the SDKs act on.
func renderAnthropicError(_ *http.Request, f *logical.GatewayFailure) *logical.Response {
	// Only strings are marshalled, so this cannot fail.
	body, _ := json.Marshal(anthropicErrorBody{
		Type: "error",
		Error: anthropicError{
			Type:    anthropicErrorType(f.Class, f.Status),
			Message: httpproxy.WardenErrorMessage(f.Err),
		},
		RequestID: f.RequestID,
	})
	headers := http.Header{"Content-Type": []string{"application/json"}}
	if f.RequestID != "" {
		// Where Anthropic puts its own request id, beside the body's request_id.
		headers.Set("request-id", f.RequestID)
	}
	return &logical.Response{StatusCode: f.Status, Headers: headers, Body: body}
}

// anthropicErrorType is the Anthropic error type for a failure: the one Anthropic
// documents for its status, except that a failure on Warden's own side is always
// an api_error — a credential Warden cannot apply is answered 401, but it is not
// the caller's authentication that failed.
func anthropicErrorType(class logical.GatewayFailureClass, status int) string {
	if class == logical.GatewayFailureInternal {
		return anthropicTypeAPI
	}
	switch status {
	case http.StatusUnauthorized:
		return anthropicTypeAuthentication
	case http.StatusForbidden:
		return anthropicTypePermission
	case http.StatusRequestEntityTooLarge:
		// A body over the cap Warden parses gateway bodies under.
		return anthropicTypeTooLarge
	case http.StatusGatewayTimeout:
		return anthropicTypeTimeout
	}
	if status >= http.StatusInternalServerError {
		// Anthropic documents no 502 or 503; api_error is its type for a
		// failure on the server's side, and its SDKs retry every 5xx.
		return anthropicTypeAPI
	}
	// Any other 4xx, a 400 above all: the request itself was unacceptable.
	return anthropicTypeInvalidRequest
}
