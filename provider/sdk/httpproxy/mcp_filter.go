package httpproxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/sdk/mcpfilter"
)

// mcpFilterCtxKey keys the per-request MCP list filter carried from
// handleGateway — which stashes it on the outbound request context — to the
// shared ReverseProxy.ModifyResponse hook that reads it back.
type mcpFilterCtxKeyT struct{}

var mcpFilterCtxKey = mcpFilterCtxKeyT{}

func withMCPListFilter(ctx context.Context, f *logical.MCPListFilter) context.Context {
	return context.WithValue(ctx, mcpFilterCtxKey, f)
}

func mcpListFilterFrom(ctx context.Context) *logical.MCPListFilter {
	f, _ := ctx.Value(mcpFilterCtxKey).(*logical.MCPListFilter)
	return f
}

// mcpGovernedCtxKey marks a request as one Warden judged per principal, which
// is a wider set than "a filter was attached".
type mcpGovernedCtxKeyT struct{}

var mcpGovernedCtxKey = mcpGovernedCtxKeyT{}

func withMCPGoverned(ctx context.Context) context.Context {
	return context.WithValue(ctx, mcpGovernedCtxKey, true)
}

func mcpGovernedFrom(ctx context.Context) bool {
	v, _ := ctx.Value(mcpGovernedCtxKey).(bool)
	return v
}

// MarkMCPResponsePrivate tells shared caches that this response is not a
// document to hand to the next caller.
//
// Exported because the MCP providers that bypass this package's reverse
// proxy — writing upstream headers onto the client's writer themselves —
// need the identical rule, and two spellings of "which directives already
// suffice" would drift.
//
// Warden creates the variance and so has to declare it. A listing is pruned
// to one principal's callable items; a resources/read is gated per principal
// before it is forwarded. An upstream describing its own unfiltered answer
// has no way to know that, and under the modern revision it may explicitly
// authorise sharing.
//
// This is the half that covers what the body rewrite cannot: the fast path
// where every item survives and the filter is skipped entirely, and
// resources/templates/list, which is cacheable but not a filterable family.
//
// It only ever strengthens. An upstream that said no-store, or already said
// private, meant something at least this restrictive and keeps it — replacing
// no-store with private would be Warden loosening a bound it does not own.
func MarkMCPResponsePrivate(h http.Header) {
	// Values, not Get: several Cache-Control field lines are legal, and Get
	// reads only the first while Set replaces them all. Reading one line and
	// writing one back would delete an upstream no-store sitting on another —
	// the precise loosening this function exists to avoid.
	values := h.Values("Cache-Control")
	if len(values) == 0 {
		h.Set("Cache-Control", "private")
		return
	}
	existing := strings.Join(values, ", ")
	if hasRestrictiveDirective(existing) {
		h.Set("Cache-Control", existing)
		return
	}
	h.Set("Cache-Control", existing+", private")
}

// hasRestrictiveDirective reports whether a Cache-Control value already
// forbids a shared cache from serving this response to another principal.
//
// Directives are compared whole, and only in their unqualified form. The
// qualified shapes — private="x-thing", no-cache="set-cookie" — restrict only
// the header fields they name and leave the response body storable and
// shareable, so they are exactly the case where the bare directive is still
// needed. A substring test would read them as sufficient and skip it.
func hasRestrictiveDirective(value string) bool {
	for _, part := range strings.Split(value, ",") {
		name := strings.TrimSpace(strings.ToLower(part))
		if i := strings.IndexByte(name, '='); i >= 0 {
			continue // qualified form: restricts named fields only
		}
		switch name {
		case "private", "no-store", "no-cache":
			return true
		}
	}
	return false
}

// installMCPListFilter wires the backend's ReverseProxy so an MCP list
// response is pruned to the items the caller may use. The hook is a no-op for
// any response whose request context carries no filter, so every non-MCP
// httpproxy provider — and every non-list MCP request — is unaffected.
func (b *proxyBackend) installMCPListFilter() {
	if b.Proxy == nil {
		return
	}
	b.Proxy.ModifyResponse = func(resp *http.Response) error {
		ctx := resp.Request.Context()
		if mcpGovernedFrom(ctx) {
			MarkMCPResponsePrivate(resp.Header)
		}
		filter := mcpListFilterFrom(ctx)
		if filter == nil {
			return nil // not an MCP list request — stream verbatim
		}
		return filterMCPListResponse(resp, filter, b.MaxBodySize())
	}
}

// filterMCPListResponse buffers a successful list response, prunes it via the
// policy-supplied keep predicate, and rewrites the body. It fails closed —
// returning an error, which surfaces the ReverseProxy's ErrorHandler 502 —
// rather than stream a body it cannot parse (e.g. still-compressed), because
// that could leak denied items. A non-success (4xx/5xx) or empty response has
// no list to leak and passes through untouched.
//
// maxBody caps the buffered response; on overflow it fails closed. The body is
// consumed to buffer it, so it is always restored (filtered or original) with
// a corrected Content-Length.
func filterMCPListResponse(resp *http.Response, filter *logical.MCPListFilter, maxBody int64) error {
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || resp.Body == nil {
		return nil
	}
	if maxBody <= 0 {
		maxBody = framework.DefaultMaxBodySize
	}

	buf, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	resp.Body.Close()
	if err != nil {
		return fmt.Errorf("mcp list filter: read upstream body: %w", err)
	}
	if int64(len(buf)) > maxBody {
		return fmt.Errorf("mcp list filter: response exceeds max_body_size")
	}
	// An empty body carries no list to leak — restore it and pass through.
	if len(buf) == 0 {
		resp.Body = io.NopCloser(bytes.NewReader(buf))
		return nil
	}

	out, _, err := mcpfilter.FilterListResponse(
		filter.ListMethod, resp.Header.Get("Content-Type"), buf, filter.Keep)
	if err != nil {
		return fmt.Errorf("mcp list filter: %w", err)
	}

	// The stream was consumed to buffer it, so restore from out regardless of
	// whether anything was dropped, and fix the framing. Accept-Encoding was
	// stripped on the outbound request, so the body is not compressed.
	resp.Body = io.NopCloser(bytes.NewReader(out))
	resp.ContentLength = int64(len(out))
	resp.TransferEncoding = nil
	resp.Header.Set("Content-Length", strconv.Itoa(len(out)))
	resp.Header.Del("Transfer-Encoding")
	// The buffered body is plain bytes; drop any encoding header so the client
	// doesn't try to decompress it. (Accept-Encoding was stripped outbound, so
	// the transport already delivered a decoded body here.)
	resp.Header.Del("Content-Encoding")
	return nil
}
