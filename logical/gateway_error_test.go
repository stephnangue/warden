// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package logical

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/hashicorp/go-multierror"
	vaultapi "github.com/hashicorp/vault/api"
	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/helper/httputil"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
)

func TestClassifyGatewayFailure(t *testing.T) {
	issue := &CredentialIssueError{Spec: "s", Err: errors.New("boom")}
	for _, tc := range []struct {
		name   string
		status int
		err    error
		want   GatewayFailureClass
	}{
		{"credential issuance, whatever its status", 500, issue, GatewayFailureMint},
		{"credential issuance, wrapped", 403, fmt.Errorf("outer: %w", issue), GatewayFailureMint},
		{"auth", http.StatusUnauthorized, ErrUnauthorized("x"), GatewayFailureAuth},
		// Status-first: core wraps the deny sentinel in a multierror.
		{"denied", http.StatusForbidden, multierror.Append(nil, sdklogical.ErrPermissionDenied), GatewayFailureDenied},
		{"unavailable", http.StatusServiceUnavailable, ErrServiceUnavailable("x"), GatewayFailureUnavailable},
		{"bad request", http.StatusBadRequest, ErrBadRequest("x"), GatewayFailureBadRequest},
		{"not found folds into bad request", http.StatusNotFound, ErrNotFound("x"), GatewayFailureBadRequest},
		{"internal", http.StatusInternalServerError, errors.New("x"), GatewayFailureInternal},
		{"bad gateway is internal", http.StatusBadGateway, errors.New("x"), GatewayFailureInternal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ClassifyGatewayFailure(tc.status, tc.err))
		})
	}
}

// CredentialIssueError must read and behave exactly like the untyped error it
// replaced, so nothing that inspected mint failures notices the change.
func TestCredentialIssueError(t *testing.T) {
	cause := errors.New("STS said no")
	e := &CredentialIssueError{Spec: "orders", Err: cause}

	assert.Equal(t, "failed to issue credential: STS said no", e.Error(),
		"the same text as the fmt.Errorf it replaced")
	assert.NotContains(t, e.Error(), "orders", "the spec name is for logs and the audit, not the message")
	assert.ErrorIs(t, e, cause)

	// Status still comes from the cause, through the wrapper.
	assert.Equal(t, http.StatusInternalServerError, GetErrorCode(e))
	assert.Equal(t, http.StatusBadRequest,
		GetErrorCode(&CredentialIssueError{Err: ErrBadRequest("spec fault")}))
	assert.Equal(t, http.StatusUnauthorized,
		GetErrorCode(&CredentialIssueError{Err: fmt.Errorf("x: %w", credential.ErrUserRequired)}))
}

// timeoutErr is a net.Error that timed out, as a dial or read does.
type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// A credential the upstream refused is answered 403, which clients do not
// retry — every retry would ask the upstream again for a credential it will
// keep refusing — and one the upstream could not issue just then is answered
// 503, which they do. The status is found through every error shape the
// drivers produce, however deeply it is wrapped.
func TestCredentialIssueError_Status(t *testing.T) {
	refused := func(status int) error {
		return &httputil.StatusError{Status: status, Err: fmt.Errorf("status %d: nope", status)}
	}
	awsResponse := func(status int) *smithyhttp.Response {
		return &smithyhttp.Response{Response: &http.Response{StatusCode: status}}
	}
	for _, tc := range []struct {
		name  string
		cause error
		want  int
	}{
		{"upstream refused (400 invalid_grant)", refused(400), http.StatusForbidden},
		{"upstream refused (401)", refused(401), http.StatusForbidden},
		{"upstream refused (403)", refused(403), http.StatusForbidden},
		{"upstream refused (404)", refused(404), http.StatusForbidden},
		{"upstream rate-limited (429)", refused(429), http.StatusServiceUnavailable},
		{"upstream timed out (408)", refused(408), http.StatusServiceUnavailable},
		{"upstream failing (502)", refused(502), http.StatusServiceUnavailable},
		{"wrapped by the driver", fmt.Errorf("gcp sts: %w", refused(403)), http.StatusForbidden},
		{"beside another wrapped error",
			fmt.Errorf("rejected: %w (%w)", credential.ErrChainedSecretRejected, refused(401)), http.StatusForbidden},
		{"wrapped by driver creation",
			fmt.Errorf("%w: azure: %w", credential.ErrDriverCreationFailed, refused(400)), http.StatusForbidden},
		{"vault refused", fmt.Errorf("vault: %w", &vaultapi.ResponseError{StatusCode: 403}), http.StatusForbidden},
		{"vault failing", &vaultapi.ResponseError{StatusCode: 503}, http.StatusServiceUnavailable},
		{"oauth2 refused", &oauth2.RetrieveError{Response: &http.Response{StatusCode: 400}}, http.StatusForbidden},
		{"aws sdk refused", fmt.Errorf("sts: %w", &awshttp.ResponseError{
			ResponseError: &smithyhttp.ResponseError{Response: awsResponse(403), Err: errors.New("AccessDenied")},
		}), http.StatusForbidden},
		{"aws sdk with no response", &awshttp.ResponseError{
			ResponseError: &smithyhttp.ResponseError{Err: errors.New("no answer")},
		}, 0},
		{"smithy refused", &smithyhttp.ResponseError{Response: awsResponse(401), Err: errors.New("x")}, http.StatusForbidden},
		{"no answer: timeout", fmt.Errorf("request failed: %w", timeoutErr{}), http.StatusServiceUnavailable},
		{"no answer: deadline", fmt.Errorf("mint: %w", context.DeadlineExceeded), http.StatusServiceUnavailable},
		{"Warden-side failure", errors.New("the identity issuer is not ready"), 0},
		{"user required", credential.ErrUserRequired, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := &CredentialIssueError{Spec: "s", Err: tc.cause}
			assert.Equal(t, tc.want, e.Status())

			// The status the response is answered with and audited under.
			want := tc.want
			if want == 0 {
				want = GetErrorCode(tc.cause)
			}
			assert.Equal(t, want, GetErrorCode(e))
			assert.Equal(t, want, ErrorResponse(e).StatusCode)
		})
	}
}
