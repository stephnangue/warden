package httpproxy

import (
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/middleware"
	"github.com/hashicorp/go-multierror"
	"github.com/stephnangue/warden/logical"
)

// The messages of the failures the gateway writes itself. They say what went
// wrong without naming the upstream's address or echoing the credential: the
// underlying error, which may carry both, goes to the log only.
var (
	errUpstreamTimeout     = errors.New("the upstream did not answer within the mount's timeout")
	errUpstreamUnreachable = errors.New("the upstream could not be reached")
	errCredentialNotUsable = errors.New("the credential could not be applied to the request")
	errUpstreamAddress     = errors.New("the upstream address could not be built")
)

// writeGatewayFailure answers a request the gateway failed itself — after core
// let it through, so core's renderer does not see it — through the spec's
// RenderGatewayError hook, and reports whether it did. On false the caller
// writes its plain-text answer, as it did before the hook existed.
//
// A failure without a request id takes it from the request's context, where the
// HTTP layer put it and where the proxy's error handler — which has only the
// HTTP request — can still reach it, so the client can report the same id core
// would have.
//
// The status written is the failure's own, which the hook's contract requires
// its response to carry anyway.
func (b *proxyBackend) writeGatewayFailure(w http.ResponseWriter, r *http.Request, f *logical.GatewayFailure) bool {
	if b.spec.RenderGatewayError == nil {
		return false
	}
	if f.RequestID == "" {
		f.RequestID = middleware.GetReqID(r.Context())
	}
	resp := b.spec.RenderGatewayError(r, f)
	if resp == nil {
		return false
	}
	for k, vs := range resp.Headers {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(f.Status)
	_, _ = w.Write(resp.Body)
	return true
}

// writeProxyFailure is the framework's ProxyErrorWriter for a spec that renders
// its errors: the proxy could not reach the upstream (502) or hear back from it
// before the request's deadline (504). Either may succeed on retry.
func (b *proxyBackend) writeProxyFailure(w http.ResponseWriter, r *http.Request, status int) bool {
	msg := errUpstreamUnreachable
	if status == http.StatusGatewayTimeout {
		msg = errUpstreamTimeout
	}
	return b.writeGatewayFailure(w, r, &logical.GatewayFailure{
		Class:  logical.GatewayFailureUnavailable,
		Status: status,
		Err:    msg,
	})
}

// WardenErrorMessage is the text of a gateway failure Warden raised itself, marked
// as Warden's so a client cannot mistake it for an error from the upstream. A
// renderer puts it where the upstream's error shape carries its message.
//
// Core collects some failures in a multierror, whose text is a bulleted list
// ("1 error occurred:\n\t* permission denied\n\n"); the messages are kept and
// joined, the bullets dropped.
func WardenErrorMessage(err error) string {
	if err == nil {
		return "Warden: request failed"
	}
	if merr, ok := err.(*multierror.Error); ok && len(merr.Errors) > 0 {
		msgs := make([]string, len(merr.Errors))
		for i, e := range merr.Errors {
			msgs[i] = e.Error()
		}
		return "Warden: " + strings.Join(msgs, "; ")
	}
	return "Warden: " + err.Error()
}
