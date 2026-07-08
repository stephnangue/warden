package httpproxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

func denyDeletePrefix(name string) bool { return !strings.HasPrefix(name, "delete_") }

func mkResp(status int, contentType, body string) *http.Response {
	h := http.Header{}
	if contentType != "" {
		h.Set("Content-Type", contentType)
	}
	h.Set("Content-Length", strconv.Itoa(len(body)))
	return &http.Response{
		StatusCode:    status,
		Header:        h,
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       httptest.NewRequest(http.MethodPost, "/gateway/", nil),
	}
}

func toolsFilter() *logical.MCPListFilter {
	return &logical.MCPListFilter{ListMethod: "tools/list", Keep: denyDeletePrefix}
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}

func TestFilterMCPListResponse_DropsDeniedTools(t *testing.T) {
	resp := mkResp(200, "application/json",
		`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"get_repo"},{"name":"delete_repo"}]}}`)

	if err := filterMCPListResponse(resp, toolsFilter(), 1<<20); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	body := readBody(t, resp)
	if strings.Contains(body, "delete_repo") {
		t.Fatalf("denied tool leaked: %s", body)
	}
	if !strings.Contains(body, "get_repo") {
		t.Fatalf("allowed tool missing: %s", body)
	}
	if got := resp.Header.Get("Content-Length"); got != strconv.Itoa(len(body)) {
		t.Fatalf("Content-Length not updated: header=%s body=%d", got, len(body))
	}
	if resp.ContentLength != int64(len(body)) {
		t.Fatalf("resp.ContentLength not updated: %d vs %d", resp.ContentLength, len(body))
	}
}

func TestFilterMCPListResponse_SSE(t *testing.T) {
	resp := mkResp(200, "text/event-stream",
		"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"get_x\"},{\"name\":\"delete_x\"}]}}\n\n")
	resp.Header.Del("Content-Length")
	resp.Header.Set("Transfer-Encoding", "chunked")

	if err := filterMCPListResponse(resp, toolsFilter(), 1<<20); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	body := readBody(t, resp)
	if strings.Contains(body, "delete_x") {
		t.Fatalf("denied tool leaked in SSE: %s", body)
	}
	if resp.Header.Get("Transfer-Encoding") != "" {
		t.Fatalf("Transfer-Encoding should be cleared after buffering")
	}
	if resp.Header.Get("Content-Length") != strconv.Itoa(len(body)) {
		t.Fatalf("Content-Length not set for buffered SSE")
	}
}

func TestFilterMCPListResponse_NonSuccessPassthrough(t *testing.T) {
	resp := mkResp(403, "application/json", `{"error":"denied"}`)
	if err := filterMCPListResponse(resp, toolsFilter(), 1<<20); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := readBody(t, resp); got != `{"error":"denied"}` {
		t.Fatalf("4xx body altered: %s", got)
	}
}

func TestFilterMCPListResponse_ErrorResponsePassthrough(t *testing.T) {
	// 200 with a JSON-RPC error (no result) — nothing to filter.
	resp := mkResp(200, "application/json",
		`{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"no"}}`)
	if err := filterMCPListResponse(resp, toolsFilter(), 1<<20); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(readBody(t, resp), "error") {
		t.Fatalf("error response should pass through")
	}
}

func TestFilterMCPListResponse_OversizeFailsClosed(t *testing.T) {
	resp := mkResp(200, "application/json",
		`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"get_repo"},{"name":"delete_repo"}]}}`)
	if err := filterMCPListResponse(resp, toolsFilter(), 10); err == nil {
		t.Fatalf("expected fail-closed error on oversize response")
	}
}

func TestFilterMCPListResponse_UnparseableFailsClosed(t *testing.T) {
	// Simulates a still-compressed / garbled 200 body: must error, not stream.
	resp := mkResp(200, "application/json", "\x1f\x8b\x08 not json")
	if err := filterMCPListResponse(resp, toolsFilter(), 1<<20); err == nil {
		t.Fatalf("expected fail-closed error on unparseable body")
	}
}

func TestFilterMCPListResponse_EmptyBodyPassthrough(t *testing.T) {
	resp := mkResp(204, "", "")
	if err := filterMCPListResponse(resp, toolsFilter(), 1<<20); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if readBody(t, resp) != "" {
		t.Fatalf("empty body should stay empty")
	}
}

func TestMCPListFilterContextRoundTrip(t *testing.T) {
	f := toolsFilter()
	ctx := withMCPListFilter(context.Background(), f)
	if got := mcpListFilterFrom(ctx); got != f {
		t.Fatalf("filter not round-tripped through context")
	}
	if mcpListFilterFrom(context.Background()) != nil {
		t.Fatalf("empty context must yield nil filter")
	}
}

// newProxyToUpstream builds a proxyBackend whose ReverseProxy forwards to
// upstreamURL, with the MCP list filter installed. Mirrors the production
// InitProxy + installMCPListFilter wiring.
func newProxyToUpstream(t *testing.T, upstreamURL string) *proxyBackend {
	t.Helper()
	b := &proxyBackend{StreamingBackend: &framework.StreamingBackend{}}
	b.InitProxy(http.DefaultTransport)
	// The proxy uses an empty Director, so point every request at the upstream.
	target, err := url.Parse(upstreamURL)
	if err != nil {
		t.Fatalf("parse upstream: %v", err)
	}
	inner := b.Proxy.Director
	b.Proxy.Director = func(r *http.Request) {
		inner(r)
		r.URL.Scheme = target.Scheme
		r.URL.Host = target.Host
		r.Host = target.Host
	}
	b.installMCPListFilter()
	return b
}

// TestModifyResponse_EndToEnd drives a request through the real ReverseProxy to
// prove the filter survives the proxy's request clone (resp.Request.Context)
// and that the list response is pruned end-to-end.
func TestModifyResponse_EndToEnd(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"get_x"},{"name":"delete_x"}]}}`)
	}))
	defer upstream.Close()

	b := newProxyToUpstream(t, upstream.URL)

	req := httptest.NewRequest(http.MethodPost, "http://gateway/gateway/", nil)
	req = req.WithContext(withMCPListFilter(req.Context(), toolsFilter()))
	rw := httptest.NewRecorder()
	b.Proxy.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("status = %d", rw.Code)
	}
	body := rw.Body.String()
	if strings.Contains(body, "delete_x") {
		t.Fatalf("denied tool leaked end-to-end: %s", body)
	}
	if !strings.Contains(body, "get_x") {
		t.Fatalf("allowed tool missing: %s", body)
	}
}

// TestModifyResponse_NoFilterPassesThrough proves a request without a filter in
// context is streamed verbatim (the hook is a no-op for non-MCP traffic).
func TestModifyResponse_NoFilterPassesThrough(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"delete_x"}]}}`)
	}))
	defer upstream.Close()

	b := newProxyToUpstream(t, upstream.URL)

	req := httptest.NewRequest(http.MethodPost, "http://gateway/gateway/", nil)
	rw := httptest.NewRecorder()
	b.Proxy.ServeHTTP(rw, req)

	if !strings.Contains(rw.Body.String(), "delete_x") {
		t.Fatalf("no-filter response must pass through unchanged: %s", rw.Body.String())
	}
}

// BenchmarkFilterMCPListResponse measures the per-list-call response overhead:
// buffer + parse + prune + re-serialize a realistic 50-tool list, half denied.
func BenchmarkFilterMCPListResponse(b *testing.B) {
	var sb strings.Builder
	sb.WriteString(`{"jsonrpc":"2.0","id":1,"result":{"tools":[`)
	for i := 0; i < 50; i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		name := "get_tool_" + strconv.Itoa(i)
		if i%2 == 1 {
			name = "delete_tool_" + strconv.Itoa(i)
		}
		sb.WriteString(`{"name":"` + name + `","description":"a tool that does a thing","inputSchema":{"type":"object","properties":{}}}`)
	}
	sb.WriteString(`]}}`)
	body := sb.String()
	filter := toolsFilter()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp := &http.Response{
			StatusCode:    http.StatusOK,
			Header:        http.Header{"Content-Type": []string{"application/json"}},
			Body:          io.NopCloser(strings.NewReader(body)),
			ContentLength: int64(len(body)),
		}
		if err := filterMCPListResponse(resp, filter, 1<<20); err != nil {
			b.Fatal(err)
		}
	}
}
