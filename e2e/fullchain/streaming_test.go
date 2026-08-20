//go:build e2e

package fullchain

import (
	"bufio"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// The response half of the chain. Every other row in this package reads the body
// to completion and asserts on the bytes, which cannot tell a streamed response
// from a buffered one — both end with the same bytes in hand. The difference is
// only in when they arrive.
//
// It matters because the providers carrying model output all set
// ParseStreamBody, and a proxy that buffered their responses would turn a
// token-by-token stream into a single reply delivered when generation finished.
// The request would still succeed, the bytes would still be right, and the
// feature would be gone.

// streamChunkGap is how long the fake upstream waits between chunks. It has to
// beat scheduling noise on a loaded CI box without making the row slow.
const streamChunkGap = 400 * time.Millisecond

// sseUpstream emits three SSE events, flushing and pausing between each.
func sseUpstream(t *testing.T) http.HandlerFunc {
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
			fmt.Fprintf(w, "data: chunk-%d\n\n", i)
			flusher.Flush()
			if i < 3 {
				time.Sleep(streamChunkGap)
			}
		}
	}
}

// TestStreaming_ResponseArrivesIncrementally proves the chain forwards a
// streamed response as it is produced rather than buffering it.
//
// The upstream pauses between chunks, so a proxy that buffered would deliver all
// three at the end and the first chunk's arrival would land near the total
// duration. Streaming shows up as the first chunk arriving while the upstream is
// still asleep before the second.
func TestStreaming_ResponseArrivesIncrementally(t *testing.T) {
	ensureEnv(t)
	upstream.SetHandler(t, sseUpstream(t))

	start := time.Now()
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

	var arrivals []time.Duration
	var chunks []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		chunks = append(chunks, line)
		arrivals = append(arrivals, time.Since(start))
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

	// The load-bearing assertion. Buffering would push the first chunk out to
	// roughly the same instant as the last; streaming separates them by the
	// upstream's own pauses.
	firstToLast := arrivals[len(arrivals)-1] - arrivals[0]
	if firstToLast < streamChunkGap {
		t.Errorf("chunks arrived %v apart, want at least %v — the response was buffered, "+
			"not streamed (arrivals: %v)", firstToLast, streamChunkGap, arrivals)
	}
}

// TestStreaming_CredentialStillInjected guards the seam between the two halves:
// a streamed response must not come at the cost of the request side. The chunks
// only flow because the upstream was reached, and it is reached only with the
// minted credential.
func TestStreaming_CredentialStillInjected(t *testing.T) {
	ensureEnv(t)
	upstream.SetHandler(t, sseUpstream(t))

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
	// Drain so the upstream finishes and the exchange is recorded whole.
	_, _ = bufio.NewReader(resp.Body).WriteTo(discard{})

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

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
