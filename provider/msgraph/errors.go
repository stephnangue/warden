package msgraph

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/sdk/httpproxy"
)

// Graph error codes, as Graph itself uses them, for the failures Warden answers
// a gateway request with. The Graph SDKs surface code and message and act on the
// status, which stays Warden's.
const (
	graphCodeInvalidToken    = "InvalidAuthenticationToken"
	graphCodeDenied          = "Authorization_RequestDenied"
	graphCodeBadRequest      = "BadRequest"
	graphCodeUnavailable     = "serviceNotAvailable"
	graphCodeGeneral         = "generalException"
	graphCodeBatchRefused    = "batchNotSupported"
	graphCodeRequestTooLarge = "requestTooLarge"
)

// graphErrorBody is Graph's error envelope.
type graphErrorBody struct {
	Error graphError `json:"error"`
}

type graphError struct {
	Code       string          `json:"code"`
	Message    string          `json:"message"`
	InnerError graphInnerError `json:"innerError"`
}

type graphInnerError struct {
	RequestID string `json:"request-id,omitempty"`
	Date      string `json:"date"`
}

// renderGraphError answers a gateway failure Warden raised itself in Graph's
// error shape, so a Graph SDK reads Warden's reason as it would Graph's own. The
// status is Warden's, unchanged.
//
// It sets no WWW-Authenticate: a challenge core attached (a claims challenge, an
// invalid user token) is kept as core set it.
func renderGraphError(_ *http.Request, f *logical.GatewayFailure) *logical.Response {
	// Only strings are marshalled, so this cannot fail.
	body, _ := json.Marshal(graphErrorBody{Error: graphError{
		Code:    graphErrorCode(f),
		Message: httpproxy.WardenErrorMessage(f.Err),
		InnerError: graphInnerError{
			RequestID: f.RequestID,
			Date:      time.Now().UTC().Format("2006-01-02T15:04:05"),
		},
	}})
	headers := http.Header{"Content-Type": []string{"application/json"}}
	if f.RequestID != "" {
		// Where Graph puts its own request id.
		headers.Set("request-id", f.RequestID)
	}
	return &logical.Response{StatusCode: f.Status, Headers: headers, Body: body}
}

// graphErrorCode is the Graph code for a failure. A user who has to
// re-authenticate is InvalidAuthenticationToken whichever class carried it; a
// refused batch has its own code; everything else follows the status.
func graphErrorCode(f *logical.GatewayFailure) string {
	switch {
	case errors.Is(f.Err, errBatchNotSupported):
		return graphCodeBatchRefused
	case errors.Is(f.Err, credential.ErrUserChallenge), errors.Is(f.Err, credential.ErrUserRequired):
		return graphCodeInvalidToken
	case f.Class == logical.GatewayFailureInternal:
		return graphCodeGeneral
	}
	switch f.Status {
	case http.StatusUnauthorized:
		return graphCodeInvalidToken
	case http.StatusForbidden:
		return graphCodeDenied
	case http.StatusRequestEntityTooLarge:
		return graphCodeRequestTooLarge
	case http.StatusServiceUnavailable, http.StatusBadGateway, http.StatusGatewayTimeout:
		return graphCodeUnavailable
	}
	if f.Status >= 400 && f.Status < 500 {
		return graphCodeBadRequest
	}
	return graphCodeGeneral
}
