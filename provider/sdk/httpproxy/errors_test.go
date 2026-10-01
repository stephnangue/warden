package httpproxy

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/go-multierror"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWardenErrorMessage(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "nil", err: nil, want: "Warden: request failed"},
		{name: "plain", err: errors.New("permission denied"), want: "Warden: permission denied"},
		{
			// Core's multierror text is a bulleted list; the messages are kept.
			name: "multierror",
			err:  multierror.Append(nil, errors.New("permission denied"), errors.New("invalid token")),
			want: "Warden: permission denied; invalid token",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, WardenErrorMessage(tt.err))
		})
	}
}

// A spec without the hook declines, which keeps Warden's generic body exactly as
// before for every provider that has not opted in.
func TestProxyBackend_RenderGatewayError_DeclinesWithoutHook(t *testing.T) {
	pb := setupBackend(t, testSpec()).(*proxyBackend)
	req := &logical.Request{HTTPRequest: httptest.NewRequest(http.MethodPost, "/gateway/x", nil)}
	f := &logical.GatewayFailure{Class: logical.GatewayFailureDenied, Status: http.StatusForbidden, Err: errors.New("denied")}

	assert.Nil(t, pb.RenderGatewayError(req, f))
}

func TestProxyBackend_RenderGatewayError_DelegatesToHook(t *testing.T) {
	spec := testSpec()
	var gotReq *http.Request
	var gotFailure *logical.GatewayFailure
	spec.RenderGatewayError = func(r *http.Request, f *logical.GatewayFailure) *logical.Response {
		gotReq, gotFailure = r, f
		return &logical.Response{StatusCode: f.Status, Body: []byte("rendered")}
	}
	pb := setupBackend(t, spec).(*proxyBackend)

	httpReq := httptest.NewRequest(http.MethodPost, "/gateway/x", nil)
	f := &logical.GatewayFailure{Class: logical.GatewayFailureDenied, Status: http.StatusForbidden, Err: errors.New("denied")}
	resp := pb.RenderGatewayError(&logical.Request{HTTPRequest: httpReq}, f)

	require.NotNil(t, resp)
	assert.Equal(t, []byte("rendered"), resp.Body)
	assert.Same(t, httpReq, gotReq, "the hook gets the HTTP request")
	assert.Same(t, f, gotFailure)
}
