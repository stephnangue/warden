// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package logical

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/hashicorp/go-multierror"
	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
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
