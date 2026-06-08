package mcp_aws

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// flushCounter wraps httptest.ResponseRecorder and counts Flush() calls. The
// counter is what proves sigv4.ForwardDirect actually delivers SSE events
// per-read rather than buffering until end-of-stream — if it buffered, the
// count would be 1 regardless of how many events the upstream wrote.
type flushCounter struct {
	*httptest.ResponseRecorder
	mu      sync.Mutex
	flushes int
}

func newFlushCounter() *flushCounter {
	return &flushCounter{ResponseRecorder: httptest.NewRecorder()}
}

func (f *flushCounter) Flush() {
	f.mu.Lock()
	f.flushes++
	f.mu.Unlock()
	f.ResponseRecorder.Flush()
}

func (f *flushCounter) Count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.flushes
}

// TestHandleGateway_SSEFlushesPerEvent verifies that sigv4.ForwardDirect's
// per-read flush loop fires once per SSE event written upstream, rather than
// buffering until the response body closes. The generic mcp provider inherits
// per-event flushing from httputil.ReverseProxy; mcp_aws is on a separate code path
// (sigv4.ForwardDirect) and needs its own regression coverage.
func TestHandleGateway_SSEFlushesPerEvent(t *testing.T) {
	const events = 3

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Errorf("upstream test server does not support flushing")
			return
		}
		for i := 1; i <= events; i++ {
			fmt.Fprintf(w, "data: event-%d\n\n", i)
			flusher.Flush()
		}
	}))
	defer upstream.Close()

	b := setupBackend(t)
	configureBackendForUpstream(t, b, upstream)

	rec := newFlushCounter()
	req, _ := makeMCPRequest("/gateway/", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, stsCredential())
	req.ResponseWriter = rec

	b.handleGateway(context.Background(), req)

	require.Equal(t, http.StatusOK, rec.Code)
	// All three events must appear in the buffered body — confirms the data
	// path is correct.
	body := rec.Body.String()
	for i := 1; i <= events; i++ {
		assert.True(t, strings.Contains(body, fmt.Sprintf("data: event-%d", i)), "event %d missing from body: %q", i, body)
	}
	// At least one Flush() per event proves per-event delivery (the upstream
	// flushes per event; sigv4.ForwardDirect's 32KB read loop happens to
	// observe each event as a discrete read because the upstream flush flushes
	// the OS socket buffer between writes).
	assert.GreaterOrEqual(t, rec.Count(), events, "expected ≥%d flushes for %d SSE events, got %d", events, events, rec.Count())
}
