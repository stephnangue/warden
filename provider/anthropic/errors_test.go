package anthropic

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sdkErrorEnvelope mirrors the error model the official Anthropic SDKs decode an
// error response into: a top-level "type":"error", the error's type and message,
// and the request id. Decoding into it strictly is the check that an SDK finds
// what it looks for, without taking a dependency on one.
type sdkErrorEnvelope struct {
	Type  string `json:"type"`
	Error struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
	RequestID string `json:"request_id"`
}

type upstreamStatusErr struct{ status int }

func (e upstreamStatusErr) Error() string   { return fmt.Sprintf("token endpoint answered %d", e.status) }
func (e upstreamStatusErr) HTTPStatus() int { return e.status }

func mintFailure(upstream int) *logical.GatewayFailure {
	issue := &logical.CredentialIssueError{Spec: "anthropic-ops", Err: upstreamStatusErr{upstream}}
	return &logical.GatewayFailure{Class: logical.GatewayFailureMint, Status: issue.Status(), Err: issue}
}

func TestRenderAnthropicError(t *testing.T) {
	failure := func(class logical.GatewayFailureClass, status int, msg string) *logical.GatewayFailure {
		return &logical.GatewayFailure{Class: class, Status: status, Err: errors.New(msg)}
	}
	tests := []struct {
		name     string
		failure  *logical.GatewayFailure
		wantType string
	}{
		{"authentication failed", failure(logical.GatewayFailureAuth, 401, "invalid token"), "authentication_error"},
		{"policy denied", failure(logical.GatewayFailureDenied, 403, "permission denied"), "permission_error"},
		{"bad request", failure(logical.GatewayFailureBadRequest, 400, "no credential spec is bound"), "invalid_request_error"},
		{"body over the parse cap", failure(logical.GatewayFailureBadRequest, 413, "request body exceeds maximum size of 10485760 bytes"), "request_too_large"},
		{"upstream unreachable", failure(logical.GatewayFailureUnavailable, 502, "the upstream could not be reached"), "api_error"},
		{"upstream timed out", failure(logical.GatewayFailureUnavailable, 504, "the upstream did not answer within the mount's timeout"), "timeout_error"},
		{"upstream refused the credential", mintFailure(http.StatusBadRequest), "permission_error"},
		{"upstream unavailable while minting", mintFailure(http.StatusBadGateway), "api_error"},
		{"internal", failure(logical.GatewayFailureInternal, 500, "audit failed"), "api_error"},
		{
			// Warden's credential lacks a field: answered 401 as it always was,
			// but not the caller's authentication.
			"credential could not be applied", failure(logical.GatewayFailureInternal, 401, "the credential could not be applied to the request"),
			"api_error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.failure.RequestID = "req-123"
			resp := renderAnthropicError(nil, tt.failure)
			require.NotNil(t, resp)

			assert.Equal(t, tt.failure.Status, resp.StatusCode, "the status is Warden's, unchanged")
			assert.Equal(t, "application/json", resp.Headers.Get("Content-Type"))
			assert.Equal(t, "req-123", resp.Headers.Get("request-id"))

			dec := json.NewDecoder(bytes.NewReader(resp.Body))
			dec.DisallowUnknownFields()
			var env sdkErrorEnvelope
			require.NoError(t, dec.Decode(&env), "body: %s", resp.Body)
			assert.Equal(t, "error", env.Type)
			assert.Equal(t, tt.wantType, env.Error.Type)
			assert.Equal(t, "Warden: "+tt.failure.Err.Error(), env.Error.Message)
			assert.Equal(t, "req-123", env.RequestID)
		})
	}
}

// No request id: neither header nor field rather than empty ones.
func TestRenderAnthropicError_NoRequestID(t *testing.T) {
	resp := renderAnthropicError(nil, &logical.GatewayFailure{Class: logical.GatewayFailureDenied, Status: 403, Err: errors.New("denied")})
	_, set := resp.Headers["Request-Id"]
	assert.False(t, set)
	var raw map[string]any
	require.NoError(t, json.Unmarshal(resp.Body, &raw))
	assert.NotContains(t, raw, "request_id")
}

func TestSpecRendersGatewayErrors(t *testing.T) {
	require.NotNil(t, Spec.RenderGatewayError)
}
