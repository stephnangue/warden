//go:build e2e

package fullchain

import (
	"bufio"
	"net/http"
	"strings"
	"testing"
	"time"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// A request that arrives at a follower crosses a second reverse proxy on its way
// to the leader, and that hop has to carry the client certificate onward: the
// listener takes it off the request and the forwarder puts it back for the
// internal hop.
//
// That makes the follower path a different chain, not the same chain further
// along. Existing coverage reaches parts of it — e2e/forwarding drives SigV4
// gateway requests through a follower, e2e/provider covers cert-transparent —
// but nothing carries two principals across it, and nothing carries a streamed
// response back through it.
//
// One property these rows deliberately do not claim: that the forwarder
// re-encodes the certificate it *parsed* rather than passing the client's header
// through. Requests here come from an address the listeners trust as a proxy, so
// the header is parsed rather than verified and the re-encoded bytes are
// identical to what was sent — the two behaviours are indistinguishable from
// outside. Telling them apart needs an in-process test at the listener.

// standbyPort resolves a follower, per test rather than cached: which node is
// following is not fixed, and an earlier row may have caused an election. The
// port is chosen by live health, so it is a follower by construction.
func standbyPort(t *testing.T) int {
	t.Helper()
	return h.GetStandbyPort(t)
}

// currentLeaderPort resolves the leader now, for reads that go to a specific
// node's own files rather than through the API.
//
// The package caches leaderPort at setup, which is fine for requests — a
// follower forwards them — but wrong for the audit log, which is written on
// whichever node served the request and read straight off that node's disk. An
// election between setup and here would send the read to the wrong file, and the
// row would fail after a ten-second poll reporting that nothing was audited,
// which is not what went wrong.
func currentLeaderPort(t *testing.T) int {
	t.Helper()
	return h.GetLeaderPort(t)
}

// TestStandby_TwoPrincipalChainIsForwarded drives the full chain at a follower.
//
// Both principals have to survive the extra hop, and they survive differently:
// the user rides Authorization, which is forwarded as-is, while the agent's
// certificate was consumed by the follower's listener and must be reconstructed
// for the internal request. A forwarder that dropped it would fail the agent; one
// that forwarded the client's original header instead of the verified
// certificate would accept a forged one.
func TestStandby_TwoPrincipalChainIsForwarded(t *testing.T) {
	ensureEnv(t)

	standby := standbyPort(t)
	probe := h.ProbePath("standby-two-principal")
	status, body, _ := h.ChainRequest(t, standby, splunkEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         splunkEnv.CertRole(),
		Path:         probe,
		Headers:      h.InertDecoyHeaders(),
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"Authorization": "Bearer " + splunkKey},
		Absent:        h.AlwaysAbsent(),
		UpstreamCalls: 1,
	})

	// The audit record is written where the request was served, which is the
	// leader — not the follower the client talked to.
	h.AssertAuditUser(t, currentLeaderPort(t), probe, h.FullChainUserSubject)

	// And it is written only there. Asserted rather than assumed: if the
	// follower also audited a request it merely forwarded, the same action would
	// appear twice across the cluster.
	if entries := h.ReadAuditEntries(t, h.NodeNumberForPort(standby), probe); len(entries) != 0 {
		t.Errorf("the follower audited a request it forwarded: %d entries", len(entries))
	}
}

// TestStandby_UntrustedCertificateIsRefusedAtTheFollower checks that entering
// through a follower confers no trust: a certificate is still validated against
// the cert mount's CA, and a request bearing an untrusted one reaches no
// upstream.
//
// The certificate is well-formed and correctly named but signed by a CA the
// mount does not trust — the same shape the leader-side row refuses, arriving by
// the other door. Read against its neighbour above, which succeeds with a
// trusted certificate over the same hop, the pair says the hop carries a
// certificate without laundering it.
//
// It does not distinguish *where* the refusal happened, only that it did and
// that nothing was forwarded. That is the honest limit: validation lives at the
// leader's cert mount either way.
func TestStandby_UntrustedCertificateIsRefusedAtTheFollower(t *testing.T) {
	ensureEnv(t)

	standby := standbyPort(t)
	otherCAPEM, otherCAKey := h.GenerateTestCA(t)
	rogue, _ := h.GenerateClientCert(t, otherCAPEM, otherCAKey, h.FullChainAgentCN)

	status, body, respHeaders := h.ChainRequest(t, standby, splunkEnv, h.ChainOpts{
		AgentCertPEM: rogue,
		Bearer:       h.FullChainUserJWT(t),
		Role:         splunkEnv.CertRole(),
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        401,
		UpstreamCalls: 0,
	})

	// Which principal was rejected matters: a user-leg failure would also be a
	// 401, and would mean the agent's certificate had been accepted.
	if challenge := respHeaders.Get("WWW-Authenticate"); strings.Contains(challenge, "invalid_token") {
		t.Errorf("the refusal names the user credential (%q); the agent's certificate should be "+
			"what was rejected", challenge)
	}
}

// TestStandby_StreamingPassesThroughTheForwardedHop sends a streamed response
// back along the follower path.
//
// The response now crosses two reverse proxies, neither of which configures a
// flush interval, so both rely on the standard library auto-flushing a body of
// unknown length. The leader-only row cannot see the second one: a follower that
// buffered would leave every direct request streaming correctly while silently
// breaking the same request made one node over.
func TestStandby_StreamingPassesThroughTheForwardedHop(t *testing.T) {
	ensureEnv(t)

	standby := standbyPort(t)
	probe := &streamProbe{}
	upstream.SetHandler(t, probe.handler(t))

	resp := h.ChainStream(t, standby, anthropicEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         anthropicEnv.CertRole(),
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
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

	// Mirrors the leader row's assertions, not just the count: a hop that
	// mangled payloads or dropped the content type while preserving cadence
	// would otherwise pass here and fail only there.
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Errorf("Content-Type: got %q, want the upstream's text/event-stream", ct)
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
		t.Errorf("through a follower the first chunk reached the client at %v, not before the "+
			"upstream finished producing at %v — the forwarded hop buffered the response",
			firstArrival, finished)
	}
}
