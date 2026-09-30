package openai

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/hashicorp/go-multierror"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sdkErrorEnvelope mirrors the error model the official OpenAI SDKs decode an
// error response into (openai-go's apierror.Error, openai-python's APIError): the
// four fields under "error". Decoding into it strictly is the check that an SDK
// finds what it looks for, without taking a dependency on one.
type sdkErrorEnvelope struct {
	Error struct {
		Message string  `json:"message"`
		Type    string  `json:"type"`
		Param   *string `json:"param"`
		Code    string  `json:"code"`
	} `json:"error"`
}

// upstreamStatusErr is an error carrying the status an upstream answered with, as
// a token endpoint's does.
type upstreamStatusErr struct{ status int }

func (e upstreamStatusErr) Error() string   { return fmt.Sprintf("token endpoint answered %d", e.status) }
func (e upstreamStatusErr) HTTPStatus() int { return e.status }

func mintFailure(upstream int) *logical.GatewayFailure {
	issue := &logical.CredentialIssueError{Spec: "openai-ops", Err: upstreamStatusErr{upstream}}
	return &logical.GatewayFailure{Class: logical.GatewayFailureMint, Status: issue.Status(), Err: issue}
}

func TestRenderOpenAIError(t *testing.T) {
	tests := []struct {
		name       string
		failure    *logical.GatewayFailure
		wantStatus int
		wantType   string
		wantCode   string
	}{
		{
			name:       "authentication failed",
			failure:    &logical.GatewayFailure{Class: logical.GatewayFailureAuth, Status: 401, Err: errors.New("invalid token")},
			wantStatus: 401, wantType: "invalid_request_error", wantCode: "warden_unauthenticated",
		},
		{
			name:       "policy denied",
			failure:    &logical.GatewayFailure{Class: logical.GatewayFailureDenied, Status: 403, Err: errors.New("permission denied")},
			wantStatus: 403, wantType: "invalid_request_error", wantCode: "warden_permission_denied",
		},
		{
			name:       "bad request",
			failure:    &logical.GatewayFailure{Class: logical.GatewayFailureBadRequest, Status: 400, Err: errors.New("no credential spec is bound")},
			wantStatus: 400, wantType: "invalid_request_error", wantCode: "warden_invalid_request",
		},
		{
			// The token endpoint refused the assertion: not retryable.
			name:       "upstream refused the credential",
			failure:    mintFailure(http.StatusBadRequest),
			wantStatus: 403, wantType: "invalid_request_error", wantCode: "warden_credential_refused",
		},
		{
			// The token endpoint was briefly unable to answer: retryable.
			name:       "upstream unavailable while minting",
			failure:    mintFailure(http.StatusBadGateway),
			wantStatus: 503, wantType: "service_unavailable_error", wantCode: "warden_credential_unavailable",
		},
		{
			name: "mint failed on Warden's side",
			failure: &logical.GatewayFailure{Class: logical.GatewayFailureMint, Status: 500,
				Err: &logical.CredentialIssueError{Spec: "openai-ops", Err: errors.New("issuer not ready")}},
			wantStatus: 500, wantType: "server_error", wantCode: "warden_internal_error",
		},
		{
			name:       "internal",
			failure:    &logical.GatewayFailure{Class: logical.GatewayFailureInternal, Status: 500, Err: errors.New("audit failed")},
			wantStatus: 500, wantType: "server_error", wantCode: "warden_internal_error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.failure.RequestID = "req-123"
			resp := renderOpenAIError(nil, tt.failure)
			require.NotNil(t, resp)

			assert.Equal(t, tt.wantStatus, resp.StatusCode, "the status is Warden's, unchanged")
			assert.Equal(t, tt.failure.Status, resp.StatusCode)
			assert.Equal(t, "application/json", resp.Headers.Get("Content-Type"))
			assert.Equal(t, "req-123", resp.Headers.Get("x-request-id"))

			dec := json.NewDecoder(bytes.NewReader(resp.Body))
			dec.DisallowUnknownFields()
			var env sdkErrorEnvelope
			require.NoError(t, dec.Decode(&env), "body: %s", resp.Body)
			assert.Equal(t, tt.wantType, env.Error.Type)
			assert.Equal(t, tt.wantCode, env.Error.Code)
			assert.Nil(t, env.Error.Param)
			// Warden's own text, marked as Warden's and otherwise verbatim.
			assert.Equal(t, "Warden: "+tt.failure.Err.Error(), env.Error.Message)

			// param is present and null, as OpenAI sends it, not omitted.
			var raw map[string]map[string]any
			require.NoError(t, json.Unmarshal(resp.Body, &raw))
			assert.Contains(t, raw["error"], "param")
		})
	}
}

// The CredentialIssueError status mapping is what the renderer's mint rows depend
// on; pin the pairing so a change there is seen here.
func TestRenderOpenAIError_MintStatusesFollowCore(t *testing.T) {
	for upstream, want := range map[int]int{400: 403, 401: 403, 403: 403, 429: 503, 500: 503} {
		assert.Equal(t, want, mintFailure(upstream).Status, "upstream %d", upstream)
	}
	_, ok := credential.UpstreamStatus(upstreamStatusErr{400})
	assert.True(t, ok)
}

func TestRenderOpenAIError_Edges(t *testing.T) {
	// No request id: no header rather than an empty one.
	resp := renderOpenAIError(nil, &logical.GatewayFailure{Class: logical.GatewayFailureDenied, Status: 403, Err: errors.New("denied")})
	_, set := resp.Headers["X-Request-Id"]
	assert.False(t, set)

	// Core's multierror keeps its messages, without the bullets.
	resp = renderOpenAIError(nil, &logical.GatewayFailure{
		Class: logical.GatewayFailureDenied, Status: 403,
		Err: multierror.Append(nil, errors.New("permission denied")),
	})
	var env sdkErrorEnvelope
	require.NoError(t, json.Unmarshal(resp.Body, &env))
	assert.Equal(t, "Warden: permission denied", env.Error.Message)
}

func TestSpecRendersGatewayErrors(t *testing.T) {
	require.NotNil(t, Spec.RenderGatewayError)
}
