package framework

import (
	"net/http"
	"sync"
	"testing"
	"time"
)

// TestStreamingBackend_ConcurrentFieldAccess proves the atomic accessors
// MaxBodySize / Timeout / TransparentConfig / Transport are race-detector
// clean when N readers and M writers hit them concurrently. The same test
// against the previous version of this file (exported fields, no atomics)
// would fire the race detector immediately.
func TestStreamingBackend_ConcurrentFieldAccess(t *testing.T) {
	t.Parallel()

	const (
		readers    = 8
		writers    = 4
		iterations = 1000
	)

	sb := &StreamingBackend{}
	sb.SetMaxBodySize(1 << 20)
	sb.SetTimeout(30 * time.Second)
	sb.SetTransparentConfig(&TransparentConfig{AutoAuthPath: "auth/jwt/"})
	sb.SetTransport(http.DefaultTransport)

	var wg sync.WaitGroup

	// Readers: hot-path accesses on every per-request field.
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_ = sb.MaxBodySize()
				_ = sb.Timeout()
				if tc := sb.TransparentConfig(); tc != nil {
					_ = tc.AutoAuthPath
				}
				_ = sb.Transport()
			}
		}()
	}

	// Writers: simulate config-write storms.
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				sb.SetMaxBodySize(int64(seed*1000 + j))
				sb.SetTimeout(time.Duration(seed+j) * time.Millisecond)
				sb.SetTransparentConfig(&TransparentConfig{
					AutoAuthPath:    "auth/jwt/",
					DefaultAuthRole: "role-rotate",
				})
				sb.SetTransport(http.DefaultTransport)
			}
		}(i)
	}

	wg.Wait()
}

// TestSwappableTransport_StoreVisible verifies that a RoundTrip dispatched
// through Transport() reaches whatever transport SetTransport installed most
// recently. Transport() returns the stable swappable wrapper itself (not the
// underlying), so callers always get the same object — the underlying is
// observed via behavior, not identity.
//
// Without the atomic.Pointer indirection in swappableTransport, the second
// SetTransport call with a different concrete type would panic. The test
// uses two distinct RoundTripper implementations to exercise that path.
func TestSwappableTransport_StoreVisible(t *testing.T) {
	t.Parallel()

	sb := &StreamingBackend{}
	sb.InitProxy(http.DefaultTransport)

	first := &countingTransport{name: "first"}
	second := &countingTransport{name: "second"}

	sb.SetTransport(first)
	_, _ = sb.Transport().RoundTrip(&http.Request{URL: nil})
	if first.count != 1 || second.count != 0 {
		t.Fatalf("after first dispatch: first=%d second=%d, want 1/0", first.count, second.count)
	}

	sb.SetTransport(second)
	_, _ = sb.Transport().RoundTrip(&http.Request{URL: nil})
	if first.count != 1 || second.count != 1 {
		t.Fatalf("after second dispatch: first=%d second=%d, want 1/1", first.count, second.count)
	}
}

type countingTransport struct {
	name  string
	count int
}

func (c *countingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	c.count++
	return nil, nil
}

// TestSwappableTransport_FirstSetTransportRace exercises the case where
// nothing has set up the swappable yet and multiple goroutines call
// SetTransport concurrently. Before the sync.Once-based ensureTransport,
// the unsynchronized b.transport field assignment would race here; under
// -race this is the regression bench.
func TestSwappableTransport_FirstSetTransportRace(t *testing.T) {
	t.Parallel()

	const goroutines = 8
	sb := &StreamingBackend{} // no pre-seed
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sb.SetTransport(http.DefaultTransport)
		}()
	}
	wg.Wait()

	// Verify the swappable was installed exactly once and dispatches correctly.
	rec := &countingTransport{name: "rec"}
	sb.SetTransport(rec)
	_, _ = sb.Transport().RoundTrip(&http.Request{URL: nil})
	if rec.count != 1 {
		t.Fatalf("RoundTrip after concurrent SetTransport then explicit SetTransport: rec.count=%d, want 1", rec.count)
	}
}

// TestSwappableTransport_StoreDifferentConcreteTypes exercises the path the
// review specifically called out: SetTransport with two different concrete
// implementations. Before atomic.Pointer (when the field was atomic.Value),
// the second Store with a different concrete type would panic.
func TestSwappableTransport_StoreDifferentConcreteTypes(t *testing.T) {
	t.Parallel()

	sb := &StreamingBackend{}

	// First a *countingTransport (custom concrete type).
	first := &countingTransport{name: "first"}
	sb.SetTransport(first)

	// Then *http.Transport (different concrete type — atomic.Value would panic).
	httpTransport := &http.Transport{}
	sb.SetTransport(httpTransport)

	// Then back to a *countingTransport.
	third := &countingTransport{name: "third"}
	sb.SetTransport(third)
	_, _ = sb.Transport().RoundTrip(&http.Request{URL: nil})
	if third.count != 1 {
		t.Fatalf("RoundTrip should reach third after three Set calls: third.count=%d", third.count)
	}
	if first.count != 0 {
		t.Fatalf("first should not have been called: first.count=%d", first.count)
	}
}
