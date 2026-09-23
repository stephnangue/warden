// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package logical

import (
	"errors"
	"net/http"
)

// GatewayFailureClass says why Warden failed a gateway request itself, before —
// or instead of — proxying it upstream. A provider that renders gateway failures
// in its clients' native wire format maps each class to that format's error
// vocabulary.
type GatewayFailureClass uint8

const (
	// GatewayFailureInternal is a server-side failure not covered by another
	// class. Clients should treat it as transient.
	GatewayFailureInternal GatewayFailureClass = iota
	// GatewayFailureAuth means the caller could not be authenticated.
	GatewayFailureAuth
	// GatewayFailureDenied means the caller was authenticated and a policy
	// refused the request.
	GatewayFailureDenied
	// GatewayFailureBadRequest means the request itself was unacceptable.
	GatewayFailureBadRequest
	// GatewayFailureUnavailable means Warden could not serve the request right
	// now; it may succeed if retried.
	GatewayFailureUnavailable
	// GatewayFailureMint means issuing the credential the request needs failed.
	// The failure's Err then holds a *CredentialIssueError, whose chain carries
	// the underlying cause — possibly an error from the upstream itself, which a
	// renderer may pass through.
	GatewayFailureMint
)

// GatewayFailure describes a gateway request that Warden failed itself.
type GatewayFailure struct {
	// Class is why the request failed.
	Class GatewayFailureClass
	// Status is the HTTP status Warden would have answered with.
	Status int
	// Err is the underlying error. Its text is what Warden would have sent.
	Err error
	// RequestID is Warden's id for the request, for the client to report.
	RequestID string
}

// GatewayErrorRenderer is an optional interface a provider backend implements to
// answer failures of its gateway requests in its clients' native wire format,
// instead of Warden's generic {"errors": [...]} body — which an SDK built for
// the upstream cannot parse.
//
// Core invokes it for failures that happen before the provider sees the request
// — authentication, policy, credential issuance — since those run in core ahead
// of routing. The provider owns everything about the answer: status, headers and
// body. Returning nil declines, keeping Warden's generic error.
//
// The returned response is what the client receives AND what the audit records,
// so its StatusCode must be the status actually intended for the wire. Core keeps
// the original error on it for the audit.
type GatewayErrorRenderer interface {
	RenderGatewayError(req *Request, failure *GatewayFailure) *Response
}

// ClassifyGatewayFailure classifies a gateway failure from the HTTP status Warden
// derived for it and its error.
//
// A credential-issuance failure is recognised by its type; everything else is
// classified by status. Status-first on purpose: core may wrap a sentinel error
// (in a multierror, say), but the status it derived already accounts for that.
func ClassifyGatewayFailure(status int, err error) GatewayFailureClass {
	var issue *CredentialIssueError
	if errors.As(err, &issue) {
		return GatewayFailureMint
	}
	switch {
	case status == http.StatusUnauthorized:
		return GatewayFailureAuth
	case status == http.StatusForbidden:
		return GatewayFailureDenied
	case status == http.StatusServiceUnavailable:
		return GatewayFailureUnavailable
	case status >= 400 && status < 500:
		return GatewayFailureBadRequest
	default:
		return GatewayFailureInternal
	}
}

// CredentialIssueError reports that issuing the credential a request needs
// failed. It marks the failure as a credential-issuance one, so a gateway error
// renderer can tell it apart from the other failures that share its status, and
// keeps the spec name for logs and the audit — it is deliberately not part of
// Error().
type CredentialIssueError struct {
	// Spec is the credential spec that failed to issue.
	Spec string
	// Err is the underlying cause.
	Err error
}

// Error returns the same text the untyped error it replaced did.
func (e *CredentialIssueError) Error() string {
	return "failed to issue credential: " + e.Err.Error()
}

// Unwrap returns the underlying cause, so errors.Is/As and GetErrorCode see
// through the wrapper.
func (e *CredentialIssueError) Unwrap() error { return e.Err }
