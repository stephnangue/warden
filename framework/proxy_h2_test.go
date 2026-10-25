package framework

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
)

// Over HTTP/2, with clients abandoning streams mid-body, every response the
// pooled proxy completes holds only its own upstream's bytes: a buffer handed
// back to the pool is never still being written to another client.
func TestProxyResponse_HTTP2PooledBuffersStayPerRequest(t *testing.T) {
	const size = 256 << 10
	sb := &StreamingBackend{Backend: &Backend{}}
	sb.InitProxy(proxyRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		n, _ := strconv.Atoi(r.Header.Get("X-Fill"))
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": {"application/octet-stream"}},
			Body:       io.NopCloser(bytes.NewReader(bytes.Repeat([]byte{byte('a' + n%26)}, size))),
			Request:    r,
		}, nil
	}))

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.URL.Scheme, r.URL.Host = "http", "upstream.example"
		sb.Proxy.ServeHTTP(w, r)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	client := srv.Client()

	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/x", nil)
			req.Header.Set("X-Fill", strconv.Itoa(i))
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			if resp.ProtoMajor != 2 {
				t.Errorf("served over HTTP/%d", resp.ProtoMajor)
				return
			}
			if i%2 == 1 {
				// Abandon the stream after its first bytes: the server sees a reset.
				io.ReadFull(resp.Body, make([]byte, 1024))
				cancel()
				return
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Errorf("request %d: %v", i, err)
				return
			}
			want := byte('a' + i%26)
			if len(body) != size || bytes.IndexFunc(body, func(r rune) bool { return byte(r) != want }) >= 0 {
				t.Errorf("request %d received %d bytes, not all %q", i, len(body), want)
			}
		}(i)
	}
	wg.Wait()
}
