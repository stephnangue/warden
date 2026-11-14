package gws

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/sdk/httpproxy"
)

// googleErrorBody is Google's error envelope. AIP-193 gives code, message and
// status; Gmail and Drive also document errors[], with reason. Both are written,
// so a client reading either finds Warden's reason where it looks for Google's.
type googleErrorBody struct {
	Error googleError `json:"error"`
}

type googleError struct {
	Code    int               `json:"code"`
	Message string            `json:"message"`
	Status  string            `json:"status"`
	Errors  []googleErrorItem `json:"errors"`
}

type googleErrorItem struct {
	Message string `json:"message"`
	Domain  string `json:"domain"`
	Reason  string `json:"reason"`
}

// renderGoogleError answers a gateway failure Warden raised itself in Google's
// error shape. The status is Warden's, unchanged. It sets no WWW-Authenticate: a
// challenge core attached, asking for the user, is kept as core set it.
func renderGoogleError(_ *http.Request, f *logical.GatewayFailure) *logical.Response {
	status, reason := googleStatus(f)
	msg := httpproxy.WardenErrorMessage(f.Err)
	// Only strings and an int are marshalled, so this cannot fail.
	body, _ := json.Marshal(googleErrorBody{Error: googleError{
		Code:    f.Status,
		Message: msg,
		Status:  status,
		Errors:  []googleErrorItem{{Message: msg, Domain: "global", Reason: reason}},
	}})
	headers := http.Header{"Content-Type": []string{"application/json; charset=UTF-8"}}
	return &logical.Response{StatusCode: f.Status, Headers: headers, Body: body}
}

// googleStatus is the Google status and reason for a failure. A user who has to
// sign in is UNAUTHENTICATED whichever class carried it; the refusals this
// provider makes have reasons of their own; everything else follows the status.
func googleStatus(f *logical.GatewayFailure) (status, reason string) {
	switch {
	case errors.Is(f.Err, credential.ErrUserChallenge), errors.Is(f.Err, credential.ErrUserRequired):
		return "UNAUTHENTICATED", "authError"
	case errors.Is(f.Err, errBatchNotSupported):
		return "INVALID_ARGUMENT", "batchNotSupported"
	case errors.Is(f.Err, errHostNotAllowed):
		return "PERMISSION_DENIED", "hostNotAllowed"
	case errors.Is(f.Err, credential.ErrUserNotAllowed):
		return "PERMISSION_DENIED", "userNotAllowed"
	case errors.Is(f.Err, errUploadNotRoutable):
		return "UNIMPLEMENTED", "uploadNotRoutable"
	case errors.Is(f.Err, errCredentialInQuery):
		return "INVALID_ARGUMENT", "credentialInQuery"
	case errors.Is(f.Err, errBodyNotJSON):
		return "INVALID_ARGUMENT", "unsupportedMediaType"
	case errors.Is(f.Err, errBodyOnRead):
		return "INVALID_ARGUMENT", "bodyNotAllowed"
	case f.Class == logical.GatewayFailureInternal:
		return "INTERNAL", "internalError"
	}
	switch f.Status {
	case http.StatusUnauthorized:
		return "UNAUTHENTICATED", "authError"
	case http.StatusForbidden:
		return "PERMISSION_DENIED", "forbidden"
	case http.StatusNotFound:
		return "NOT_FOUND", "notFound"
	case http.StatusRequestEntityTooLarge:
		return "INVALID_ARGUMENT", "uploadTooLarge"
	case http.StatusTooManyRequests:
		return "RESOURCE_EXHAUSTED", "rateLimitExceeded"
	case http.StatusBadGateway, http.StatusServiceUnavailable:
		return "UNAVAILABLE", "backendError"
	case http.StatusGatewayTimeout:
		return "DEADLINE_EXCEEDED", "backendError"
	}
	if f.Status >= 400 && f.Status < 500 {
		return "INVALID_ARGUMENT", "badRequest"
	}
	return "INTERNAL", "internalError"
}
