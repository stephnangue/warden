package openai

import (
	"encoding/json"
	"net/http"

	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/sdk/httpproxy"
)

// OpenAI's error types, as its API documents them and its real responses carry.
// The SDKs classify an error by its HTTP status; type and code are what they
// surface to the caller.
const (
	openaiTypeInvalidRequest     = "invalid_request_error"
	openaiTypeServiceUnavailable = "service_unavailable_error"
	openaiTypeServer             = "server_error"
)

// The codes of the failures Warden raises itself. Each starts with "warden_", so
// a caller can tell the gateway refused the request from OpenAI refusing it —
// they call for different fixes.
const (
	codeUnauthenticated       = "warden_unauthenticated"
	codePermissionDenied      = "warden_permission_denied"
	codeInvalidRequest        = "warden_invalid_request"
	codeCredentialRefused     = "warden_credential_refused"
	codeCredentialUnavailable = "warden_credential_unavailable"
	codeInternal              = "warden_internal_error"
)

// openaiErrorBody is OpenAI's error envelope. Param is always null: a failure
// Warden raises is about the request as a whole, never one of its parameters.
type openaiErrorBody struct {
	Error openaiError `json:"error"`
}

type openaiError struct {
	Message string  `json:"message"`
	Type    string  `json:"type"`
	Param   *string `json:"param"`
	Code    string  `json:"code"`
}

// renderOpenAIError answers a gateway failure Warden raised itself in OpenAI's
// error shape, so an OpenAI SDK surfaces Warden's reason instead of failing to
// parse Warden's generic body. The status is Warden's, unchanged: it already
// says whether a retry can help, which is what the SDKs act on.
func renderOpenAIError(_ *http.Request, f *logical.GatewayFailure) *logical.Response {
	errType, code := openaiErrorFor(f.Class, f.Status)
	// Only strings are marshalled, so this cannot fail.
	body, _ := json.Marshal(openaiErrorBody{Error: openaiError{
		Message: httpproxy.WardenErrorMessage(f.Err),
		Type:    errType,
		Code:    code,
	}})
	headers := http.Header{"Content-Type": []string{"application/json"}}
	if f.RequestID != "" {
		// Where OpenAI puts its own request id, and where its SDKs read it from.
		headers.Set("x-request-id", f.RequestID)
	}
	return &logical.Response{StatusCode: f.Status, Headers: headers, Body: body}
}

// openaiErrorFor puts a failure in OpenAI's terms: the error type for its status,
// and Warden's code for why it failed.
func openaiErrorFor(class logical.GatewayFailureClass, status int) (errType, code string) {
	switch class {
	case logical.GatewayFailureAuth:
		return openaiTypeInvalidRequest, codeUnauthenticated
	case logical.GatewayFailureDenied:
		return openaiTypeInvalidRequest, codePermissionDenied
	case logical.GatewayFailureBadRequest:
		return openaiTypeInvalidRequest, codeInvalidRequest
	case logical.GatewayFailureMint:
		switch {
		case status == http.StatusServiceUnavailable:
			// The upstream, or the way to it, was briefly unable to answer.
			return openaiTypeServiceUnavailable, codeCredentialUnavailable
		case status >= http.StatusInternalServerError:
			return openaiTypeServer, codeInternal
		default:
			// The upstream refused the credential Warden presented: the request
			// will not succeed until the configuration changes.
			return openaiTypeInvalidRequest, codeCredentialRefused
		}
	default:
		return openaiTypeServer, codeInternal
	}
}
