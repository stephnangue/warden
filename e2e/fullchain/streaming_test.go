//go:build e2e

package fullchain

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// The response half of the chain. Every other row in this package reads the body
// to completion and asserts on the bytes, which cannot tell a streamed response
// from a buffered one — both end with the same bytes in hand. The difference is
// only in when they arrive.
//
// Nothing configures a flush interval on either reverse proxy in the tree, so
// incremental delivery rests on the standard library's own rule: it auto-flushes
// a response whose length is unknown, which is what an SSE body is. The wrapper
// Warden puts around the ResponseWriter therefore has to forward Flush through
// to the underlying writer, and that is the surface this row guards. A wrapper
// that swallowed Flush would turn a token-by-token stream into one reply
// delivered when generation finished — same status, same bytes, feature gone.

// streamChunkGap is how long the fake upstream waits between chunks. It only has
// to be long enough to be unambiguous; the assertion does not compare against it.
const streamChunkGap = 400 * time.Millisecond

// streamProbe is an upstream that emits SSE events and records when it finished
// producing them. Comparing that instant against the client's first chunk is
// what makes the assertion threshold-free.
type streamProbe struct {
	mu         sync.Mutex
	lastSentAt time.Time
}

func (s *streamProbe) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Error("upstream ResponseWriter cannot flush; the test cannot emit a stream")
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		flusher.Flush()

		for i := 1; i <= 3; i++ {
			if i > 1 {
				time.Sleep(streamChunkGap)
			}
			fmt.Fprintf(w, "data: chunk-%d\n\n", i)
			flusher.Flush()
		}

		s.mu.Lock()
		s.lastSentAt = time.Now()
		s.mu.Unlock()
	}
}

func (s *streamProbe) finishedAt() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastSentAt
}

// TestStreaming_ResponseArrivesIncrementally proves the chain forwards a
// streamed response as it is produced rather than buffering it.
//
// The assertion is the definition rather than a threshold: the client held
// chunk-1 before the upstream had finished writing chunk-3. That ordering cannot
// be manufactured by load — a slow machine delays both sides — so unlike a
// "chunks arrived N apart" bound there is no margin to tune and nothing to go
// flaky.
//
// What it catches is a response withheld until complete. It does not distinguish
// degrees of lag: a proxy that released each chunk only when the next arrived
// would still deliver chunk-1 early and still pass, which is defensible, since
// such a proxy is streaming — just one chunk behind. Verified by mutation in both
// directions: removing the upstream's flushes fails this row, while flushing one
// chunk late passes it.
func TestStreaming_ResponseArrivesIncrementally(t *testing.T) {
	ensureEnv(t)

	probe := &streamProbe{}
	upstream.SetHandler(t, probe.handler(t))

	resp := h.ChainStream(t, leaderPort, anthropicEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         anthropicEnv.CertRole(),
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Errorf("Content-Type: got %q, want the upstream's text/event-stream", ct)
	}

	var chunks []string
	var firstArrival time.Time
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if firstArrival.IsZero() {
			firstArrival = time.Now()
		}
		chunks = append(chunks, line)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("reading the stream: %v", err)
	}

	if len(chunks) != 3 {
		t.Fatalf("got %d chunks %q, want 3", len(chunks), chunks)
	}
	for i, want := range []string{"data: chunk-1", "data: chunk-2", "data: chunk-3"} {
		if chunks[i] != want {
			t.Errorf("chunk %d: got %q, want %q", i+1, chunks[i], want)
		}
	}

	finished := probe.finishedAt()
	if finished.IsZero() {
		t.Fatal("the upstream never recorded finishing; it did not run to completion")
	}
	if !firstArrival.Before(finished) {
		t.Errorf("the first chunk reached the client at %v, not before the upstream finished "+
			"producing at %v — the response was buffered rather than streamed",
			firstArrival, finished)
	}
}

// TestStreaming_HelperCarriesTheSameRequest checks the streaming helper, not the
// server. Credential injection is request-side and finishes before the upstream
// writes a byte, so the server path is identical whichever shape the response
// takes — the injection itself is already covered by the anthropic rows.
//
// What is worth checking is that the hand-rolled request in ChainStream carries
// the same credentials and decoys as the buffered path, and that an upstream
// with a replaced handler still records what it received. A divergence here
// would make every future streaming row test something subtly different from its
// non-streaming neighbours.
func TestStreaming_HelperCarriesTheSameRequest(t *testing.T) {
	ensureEnv(t)

	probe := &streamProbe{}
	upstream.SetHandler(t, probe.handler(t))

	resp := h.ChainStream(t, leaderPort, anthropicEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         anthropicEnv.CertRole(),
		Headers:      h.InertDecoyHeaders(),
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}
	// Drained so the upstream handler runs to completion and does not outlive the
	// test. The request was recorded on arrival, before the handler ran, so this
	// is about the server goroutine rather than about the recording.
	_, _ = io.Copy(io.Discard, resp.Body)

	got := upstream.Last(t).Header
	if v := got.Get("x-api-key"); v != anthropicKey {
		t.Errorf("upstream x-api-key: got %q, want the minted credential %q", v, anthropicKey)
	}
	for _, name := range h.AlwaysAbsent() {
		if v := got.Get(name); v != "" {
			t.Errorf("%s should not have been forwarded, got %q", name, v)
		}
	}
}
