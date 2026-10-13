package httpproxy

import (
	"context"
	"strings"

	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
)

// RewriteContext is what a spec's ModifyResponse gets to rewrite a response with.
type RewriteContext struct {
	// Prefix is the external URL of this mount's gateway as the client addressed
	// it, through "/gateway" and without a trailing slash — for example
	// https://warden.example.com/v1/team-a/msgraph/role/m365/gateway. An upstream
	// URL rewritten onto it routes back through Warden under the same role.
	Prefix string

	// MaxBodySize bounds how much of a response the hook may buffer.
	MaxBodySize int64
}

type rewriteCtxKeyT struct{}

var rewriteCtxKey = rewriteCtxKeyT{}

func withRewriteContext(ctx context.Context, rc RewriteContext) context.Context {
	return context.WithValue(ctx, rewriteCtxKey, rc)
}

func rewriteContextFrom(ctx context.Context) (RewriteContext, bool) {
	rc, ok := ctx.Value(rewriteCtxKey).(RewriteContext)
	return rc, ok
}

// rewritePrefix builds RewriteContext.Prefix for a request, or "" when it cannot:
// no external base is configured, or the gateway segment is not where a gateway
// path puts it.
//
// It is built from the path core recorded before routing (AuditPath), because by
// the time a response arrives the role-in-path form has been rewritten away; the
// prefix therefore keeps whichever form the client used — role in the path, or
// none with X-Warden-Role or default_role — and a link rewritten onto it is
// answered the way the original request was. The base comes from Warden's own
// configuration, never from the request.
func (b *proxyBackend) rewritePrefix(ctx context.Context, req *logical.Request) string {
	if b.externalBaseURL == nil {
		return ""
	}
	base := strings.TrimRight(b.externalBaseURL(ctx), "/")
	if base == "" {
		return ""
	}
	segs := strings.SplitN(strings.TrimPrefix(req.AuditPath, "/"), "/", 4)
	var gateway string
	switch {
	case len(segs) >= 1 && segs[0] == "gateway":
		gateway = "gateway"
	case len(segs) >= 3 && segs[0] == "role" && segs[1] != "" && segs[2] == "gateway":
		gateway = "role/" + segs[1] + "/gateway"
	default:
		return ""
	}
	nsPath := ""
	if ns, err := namespace.FromContext(ctx); err == nil && ns != nil {
		nsPath = ns.Path
	}
	return base + "/v1/" + nsPath + req.MountPoint + gateway
}
