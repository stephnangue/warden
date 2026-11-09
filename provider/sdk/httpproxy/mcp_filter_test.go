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
		sb.WriteString(`{"name":"`)
		sb.WriteString(name)
		sb.WriteString(`","description":"a tool that does a thing","inputSchema":{"type":"object","properties":{}}}`)
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

// =============================================================================
// Cache-Control on governed responses
// =============================================================================

func TestMarkMCPResponsePrivate(t *testing.T) {
	cases := []struct {
		name     string
		existing string
		want     string
	}{
		{"no header", "", "private"},
		{"public is narrowed", "public, max-age=60", "public, max-age=60, private"},
		{"max-age alone gains private", "max-age=60", "max-age=60, private"},
		// Only ever strengthens: an upstream that said no-store meant
		// something stricter than private, and replacing it would be Warden
		// loosening a bound it does not own.
		{"no-store survives untouched", "no-store", "no-store"},
		{"no-cache survives untouched", "no-cache", "no-cache"},
		{"already private is left alone", "private", "private"},
		{"private among others is left alone", "max-age=0, private", "max-age=0, private"},
		{"casing is not a way around it", "NO-STORE", "NO-STORE"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			if tc.existing != "" {
				h.Set("Cache-Control", tc.existing)
			}

			MarkMCPResponsePrivate(h)

			if got := h.Get("Cache-Control"); got != tc.want {
				t.Errorf("Cache-Control = %q, want %q", got, tc.want)
			}
		})
	}
}

// The header half is what covers the responses the body rewrite cannot: a
// listing where every item survived and the filter was skipped, a
// resources/read gated request-side, and resources/templates/list, which is
// cacheable but not a filterable family.
func TestModifyResponse_MarksGovernedResponsesPrivate(t *testing.T) {
	spec := testSpec()
	pb := setupBackend(t, spec).(*proxyBackend)

	cases := []struct {
		name     string
		governed bool
		want     string
	}{
		{"governed request is marked", true, "private"},
		{"non-MCP request is untouched", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if tc.governed {
				ctx = withMCPGoverned(ctx)
			}
			resp := &http.Response{
				StatusCode: 200,
				Header:     http.Header{},
				Request:    httptest.NewRequest("POST", "/v1/test/gateway/", nil).WithContext(ctx),
			}

			if err := pb.Proxy.ModifyResponse(resp); err != nil {
				t.Fatalf("ModifyResponse: %v", err)
			}

			if got := resp.Header.Get("Cache-Control"); got != tc.want {
				t.Errorf("Cache-Control = %q, want %q", got, tc.want)
			}
		})
	}
}

// The predicate that decides which mounts declare their responses private is
// the whole blast radius of this feature. proxyBackend implements
// MCPPolicyEnforced for every provider it backs, so core installs an empty
// descriptor on github, openai and git traffic too — reading that as
// "governed" would mark the entire provider surface uncacheable by any
// shared cache. Driven through handleGateway rather than by building the
// context by hand, so the wiring itself is covered.
func TestHandleGateway_OnlyMCPEnforcingMountsMarkResponsesPrivate(t *testing.T) {
	cases := []struct {
		name        string
		enforcesMCP bool
		want        string
	}{
		{"MCP-enforcing mount", true, "private"},
		{"ordinary REST provider", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			defer upstream.Close()

			spec := testSpec()
			spec.DefaultURL = upstream.URL
			spec.ExtractCredentials = func(*logical.Request) (map[string]string, error) {
				return map[string]string{"Authorization": "Bearer test"}, nil
			}
			if tc.enforcesMCP {
				spec.ShouldEnforceMCPPolicy = func(*logical.Request) bool { return true }
			}

			pb := setupBackend(t, spec).(*proxyBackend)
			pb.providerURL = upstream.URL

			rec := httptest.NewRecorder()
			pb.handleGateway(context.Background(), &logical.Request{
				HTTPRequest:    httptest.NewRequest("POST", "/v1/test/gateway/", nil),
				ResponseWriter: rec,
				// The empty sentinel core installs for every httpproxy
				// backend, MCP-enforcing or not.
				MCPDescriptor: &logical.MCPRequestDescriptor{},
			})

			if got := rec.Header().Get("Cache-Control"); got != tc.want {
				t.Errorf("Cache-Control = %q, want %q", got, tc.want)
			}
		})
	}
}

// Several Cache-Control field lines are legal HTTP. Reading only the first
// and writing one back would delete an upstream no-store sitting on another —
// exactly the loosening the strengthen-only rule exists to prevent.
func TestMarkMCPResponsePrivate_PreservesEveryFieldLine(t *testing.T) {
	h := http.Header{}
	h.Add("Cache-Control", "public")
	h.Add("Cache-Control", "no-store")

	MarkMCPResponsePrivate(h)

	got := h.Get("Cache-Control")
	if !strings.Contains(got, "no-store") {
		t.Errorf("Cache-Control = %q, dropped the upstream no-store", got)
	}
	if strings.Contains(got, "private") {
		t.Errorf("Cache-Control = %q, appended private to an already-restrictive value", got)
	}
}

// A qualified directive restricts only the header fields it names and leaves
// the body storable and shareable, so it is precisely where the bare
// directive is still needed. A substring test would read it as sufficient.
func TestMarkMCPResponsePrivate_QualifiedDirectivesAreNotSufficient(t *testing.T) {
	cases := []string{
		`private="x-session-hint", max-age=600`,
		`public, no-cache="set-cookie"`,
	}
	for _, existing := range cases {
		t.Run(existing, func(t *testing.T) {
			h := http.Header{}
			h.Set("Cache-Control", existing)

			MarkMCPResponsePrivate(h)

			if got := h.Get("Cache-Control"); !strings.HasSuffix(got, ", private") {
				t.Errorf("Cache-Control = %q, want a bare private appended", got)
			}
		})
	}
}
