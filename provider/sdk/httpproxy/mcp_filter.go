package httpproxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"

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

// installMCPListFilter wires the backend's ReverseProxy so an MCP list
// response is pruned to the items the caller may use. The hook is a no-op for
// any response whose request context carries no filter, so every non-MCP
// httpproxy provider — and every non-list MCP request — is unaffected.
func (b *proxyBackend) installMCPListFilter() {
	if b.Proxy == nil {
		return
	}
	b.Proxy.ModifyResponse = func(resp *http.Response) error {
		filter := mcpListFilterFrom(resp.Request.Context())
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
