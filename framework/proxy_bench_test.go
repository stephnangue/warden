package framework

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// BenchmarkProxyResponse measures proxying one 64 KiB upstream response to the
// client through InitProxy's ReverseProxy, against an in-memory transport so
// only the proxy's own cost is counted.
func BenchmarkProxyResponse(b *testing.B) {
	payload := bytes.Repeat([]byte("x"), 64<<10)
	sb := &StreamingBackend{Backend: &Backend{}}
	sb.InitProxy(proxyRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": {"application/json"}},
			Body:       io.NopCloser(bytes.NewReader(payload)),
			Request:    r,
		}, nil
	}))
	req := httptest.NewRequest(http.MethodGet, "http://upstream.example/v1/data", nil)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		sb.Proxy.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || rec.Body.Len() != len(payload) {
			b.Fatalf("status %d, %d bytes", rec.Code, rec.Body.Len())
		}
	}
}
