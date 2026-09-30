package httpproxy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/middleware"
	"github.com/hashicorp/go-multierror"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingRenderer is a RenderGatewayError hook that records the failure it was
// asked to render and answers with a fixed JSON body.
func recordingRenderer(got **logical.GatewayFailure) func(*http.Request, *logical.GatewayFailure) *logical.Response {
	return func(_ *http.Request, f *logical.GatewayFailure) *logical.Response {
		*got = f
		return &logical.Response{
			StatusCode: f.Status,
			Headers:    http.Header{"Content-Type": []string{"application/json"}},
			Body:       []byte(`{"rendered":"` + WardenErrorMessage(f.Err) + `"}`),
		}
	}
}

// The gateway's own failures — after core let the request through, so core's
// renderer never sees them — go through the same hook when the spec sets it.
func TestHandleGateway_RendersItsOwnFailures(t *testing.T) {
	t.Run("credential the extractor cannot use", func(t *testing.T) {
		var got *logical.GatewayFailure
		spec := testSpec()
		spec.RenderGatewayError = recordingRenderer(&got)
		pb := setupBackend(t, spec).(*proxyBackend)

		rec := httptest.NewRecorder()
		httpReq := httptest.NewRequest("POST", "/test/gateway/v1/endpoint", nil)
		pb.handleGateway(context.Background(), &logical.Request{HTTPRequest: httpReq, ResponseWriter: rec, RequestID: "req-42"})

		require.NotNil(t, got)
		// Warden's fault, classed so; the 401 it has always been answered with is kept.
		assert.Equal(t, logical.GatewayFailureInternal, got.Class)
		assert.Equal(t, http.StatusUnauthorized, got.Status)
		assert.Equal(t, "req-42", got.RequestID, "the id the HTTP layer gave the request")
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
		assert.Equal(t, `{"rendered":"Warden: the credential could not be applied to the request"}`, rec.Body.String())
	})

	t.Run("upstream unreachable", func(t *testing.T) {
		gone := httptest.NewServer(http.NotFoundHandler())
		gone.Close()

		var got *logical.GatewayFailure
		spec := testSpec()
		spec.RenderGatewayError = recordingRenderer(&got)
		pb := setupBackend(t, spec).(*proxyBackend)
		pb.providerURL = gone.URL

		rec := httptest.NewRecorder()
		httpReq := httptest.NewRequest("POST", "/test/gateway/v1/endpoint", strings.NewReader(`{}`))
		httpReq.URL, _ = url.Parse(gone.URL + "/test/gateway/v1/endpoint")
		// The proxy's error handler has only the HTTP request, whose context
		// descends from the one the HTTP layer tagged with the request id.
		ctx := context.WithValue(context.Background(), middleware.RequestIDKey, "req-43")
		pb.handleGateway(ctx, &logical.Request{
			HTTPRequest:    httpReq,
			ResponseWriter: rec,
			Credential:     &credential.Credential{Type: credential.TypeAPIKey, Data: map[string]string{"api_key": "sk-test"}},
		})

		require.NotNil(t, got)
		assert.Equal(t, logical.GatewayFailureUnavailable, got.Class)
		assert.Equal(t, http.StatusBadGateway, got.Status)
		assert.Equal(t, "req-43", got.RequestID, "read off the context")
		assert.Equal(t, http.StatusBadGateway, rec.Code)
		assert.Equal(t, `{"rendered":"Warden: the upstream could not be reached"}`, rec.Body.String())
		assert.NotContains(t, rec.Body.String(), strings.TrimPrefix(gone.URL, "http://"),
			"the upstream's address stays in the log")
	})

	t.Run("without the hook the plain text is kept", func(t *testing.T) {
		pb := setupBackend(t, testSpec()).(*proxyBackend)
		assert.Nil(t, pb.StreamingBackend.ProxyErrorWriter, "no writer is installed for a spec that does not render")

		rec := httptest.NewRecorder()
		pb.handleGateway(context.Background(), &logical.Request{
			HTTPRequest:    httptest.NewRequest("POST", "/test/gateway/v1/endpoint", nil),
			ResponseWriter: rec,
		})
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Equal(t, "Unauthorized\n", rec.Body.String())
	})

	t.Run("a declining hook falls back to the plain text", func(t *testing.T) {
		spec := testSpec()
		spec.RenderGatewayError = func(*http.Request, *logical.GatewayFailure) *logical.Response { return nil }
		pb := setupBackend(t, spec).(*proxyBackend)

		rec := httptest.NewRecorder()
		pb.handleGateway(context.Background(), &logical.Request{
			HTTPRequest:    httptest.NewRequest("POST", "/test/gateway/v1/endpoint", nil),
			ResponseWriter: rec,
		})
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Equal(t, "Unauthorized\n", rec.Body.String())
	})
}

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
