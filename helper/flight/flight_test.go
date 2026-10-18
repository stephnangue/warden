package flight

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// recv waits for ch, failing instead of hanging.
func recv[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		var zero T
		return zero
	}
}

type outcome struct {
	v   int
	err error
}

// gate is shared work that holds until opened, counting the calls that ran.
type gate struct {
	entered chan struct{}
	open    chan struct{}
	once    sync.Once
	calls   atomic.Int32
}

func newGate(t *testing.T) *gate {
	g := &gate{entered: make(chan struct{}, 8), open: make(chan struct{})}
	t.Cleanup(g.release)
	return g
}

func (g *gate) release() { g.once.Do(func() { close(g.open) }) }

// work returns 42 once opened, or its context's error if that ended first.
func (g *gate) work(ctx context.Context) (int, error) {
	g.calls.Add(1)
	g.entered <- struct{}{}
	select {
	case <-g.open:
		return 42, ctx.Err()
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

func do(g *Group[int], ctx context.Context, w *gate) <-chan outcome {
	out := make(chan outcome, 1)
	go func() {
		v, err := g.Do(ctx, "k", w.work)
		out <- outcome{v, err}
	}()
	return out
}

func TestDo_CoalescesConcurrentCalls(t *testing.T) {
	g := New[int]("test", time.Minute, nil)
	w := newGate(t)
	first := do(g, context.Background(), w)
	recv(t, w.entered, "the shared call to start")
	second := do(g, context.Background(), w)
	time.Sleep(20 * time.Millisecond) // let the second caller join
	w.release()

	for _, ch := range []<-chan outcome{first, second} {
		got := recv(t, ch, "a caller's result")
		if got.err != nil || got.v != 42 {
			t.Fatalf("got %v, %v; want 42", got.v, got.err)
		}
	}
	if n := w.calls.Load(); n != 1 {
		t.Errorf("the work ran %d times, want once", n)
	}
}

// The caller that started the shared call giving up must not fail the others.
func TestDo_StarterCancellationDoesNotFailOthers(t *testing.T) {
	g := New[int]("test", time.Minute, nil)
	w := newGate(t)
	starterCtx, cancelStarter := context.WithCancel(context.Background())
	starter := do(g, starterCtx, w)
	recv(t, w.entered, "the shared call to start")
	other := do(g, context.Background(), w)
	time.Sleep(20 * time.Millisecond)

	cancelStarter()
	if err := recv(t, starter, "the starter to return").err; !errors.Is(err, context.Canceled) {
		t.Fatalf("starter: %v, want context.Canceled", err)
	}
	w.release()
	if got := recv(t, other, "the other caller's result"); got.err != nil || got.v != 42 {
		t.Fatalf("other caller got %v, %v; want 42", got.v, got.err)
	}
}

// A waiter whose own context ends returns at once; the shared call carries on.
func TestDo_WaiterReturnsOnItsOwnContext(t *testing.T) {
	g := New[int]("test", time.Minute, nil)
	w := newGate(t)
	starter := do(g, context.Background(), w)
	recv(t, w.entered, "the shared call to start")

	waiterCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := recv(t, do(g, waiterCtx, w), "the waiter to return").err; !errors.Is(err, context.Canceled) {
		t.Fatalf("waiter: %v, want context.Canceled", err)
	}
	w.release()
	if got := recv(t, starter, "the starter's result"); got.err != nil {
		t.Fatalf("starter: %v", got.err)
	}
}

// The shared call is bounded by the Group's timeout, not by any caller.
func TestDo_TimeoutBoundsTheSharedCall(t *testing.T) {
	g := New[int]("test", 50*time.Millisecond, nil)
	w := newGate(t)
	got := recv(t, do(g, context.Background(), w), "the bounded call")
	if !errors.Is(got.err, context.DeadlineExceeded) {
		t.Fatalf("got %v, want the group's deadline", got.err)
	}
}

// Work in flight ends when its owner's lifetime does.
func TestDo_LifetimeEndsTheSharedCall(t *testing.T) {
	life, end := context.WithCancel(context.Background())
	g := New[int]("test", time.Minute, nil, WithLifetime(func() context.Context { return life }))
	w := newGate(t)
	result := do(g, context.Background(), w)
	recv(t, w.entered, "the shared call to start")

	end()
	if got := recv(t, result, "the call to end"); !errors.Is(got.err, context.Canceled) {
		t.Fatalf("got %v, want the lifetime's cancellation", got.err)
	}
}

// Values on the caller's context reach the shared work.
func TestDo_KeepsContextValues(t *testing.T) {
	type key struct{}
	g := New[string]("test", time.Minute, nil)
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), key{}, "tenant-a"))
	defer cancel()
	got, err := g.Do(ctx, "k", func(ctx context.Context) (string, error) {
		v, _ := ctx.Value(key{}).(string)
		return v, nil
	})
	if err != nil || got != "tenant-a" {
		t.Fatalf("got %q, %v", got, err)
	}
}

// A panic in the shared work reaches every waiter as an error; the process lives.
func TestDo_PanicBecomesAnErrorForEveryWaiter(t *testing.T) {
	g := New[int]("test", time.Minute, nil)
	entered := make(chan struct{})
	open := make(chan struct{})
	panicky := func(context.Context) (int, error) {
		close(entered)
		<-open
		panic("driver bug")
	}

	results := make(chan error, 2)
	go func() { _, err := g.Do(context.Background(), "k", panicky); results <- err }()
	recv(t, entered, "the shared call to start")
	go func() { _, err := g.Do(context.Background(), "k", panicky); results <- err }()
	time.Sleep(20 * time.Millisecond)
	close(open)

	for i := 0; i < 2; i++ {
		if err := recv(t, results, "a waiter's error"); !errors.Is(err, ErrPanicked) {
			t.Fatalf("waiter %d: %v, want ErrPanicked", i, err)
		}
	}
}

// A failure is not kept: the next call runs the work again.
func TestDo_FailureIsNotRemembered(t *testing.T) {
	g := New[int]("test", time.Minute, nil)
	var calls atomic.Int32
	fn := func(context.Context) (int, error) {
		if calls.Add(1) == 1 {
			return 0, errors.New("boom")
		}
		return 7, nil
	}
	if _, err := g.Do(context.Background(), "k", fn); err == nil {
		t.Fatal("the first call should fail")
	}
	if v, err := g.Do(context.Background(), "k", fn); err != nil || v != 7 {
		t.Fatalf("second call: %v, %v", v, err)
	}
}

// Evict lets a fresh call start while a stale one is in flight.
func TestEvict_StartsAFreshCall(t *testing.T) {
	g := New[int]("test", time.Minute, nil)
	w := newGate(t)
	stale := do(g, context.Background(), w)
	recv(t, w.entered, "the stale call to start")

	g.Evict("k")
	fresh := make(chan outcome, 1)
	go func() {
		v, err := g.Do(context.Background(), "k", func(context.Context) (int, error) { return 9, nil })
		fresh <- outcome{v, err}
	}()
	if got := recv(t, fresh, "the fresh call"); got.v != 9 || got.err != nil {
		t.Fatalf("fresh call: %v, %v", got.v, got.err)
	}
	w.release()
	recv(t, stale, "the stale call")
}

func doKey(g *Group[int], ctx context.Context, key string, w *gate) <-chan outcome {
	out := make(chan outcome, 1)
	go func() {
		v, err := g.Do(ctx, key, w.work)
		out <- outcome{v, err}
	}()
	return out
}

// Past the cap, a call runs on its starter's own context: that caller going away
// ends it at once, while the call under the cap stays detached and carries on.
// The count returns to zero either way.
func TestMaxDetached_CallsPastTheCapKeepTheirCallersCancellation(t *testing.T) {
	g := New[int]("test", time.Minute, nil, WithMaxDetached(1))
	under := newGate(t)
	underCtx, cancelUnder := context.WithCancel(context.Background())
	underResult := doKey(g, underCtx, "under", under)
	recv(t, under.entered, "the call under the cap to start")

	over := newGate(t)
	overCtx, cancelOver := context.WithCancel(context.Background())
	overResult := doKey(g, overCtx, "over", over)
	recv(t, over.entered, "the call past the cap to start")

	// Both callers give up. Only the call past the cap is ended by it.
	cancelOver()
	cancelUnder()
	if got := recv(t, overResult, "the call past the cap"); !errors.Is(got.err, context.Canceled) {
		t.Fatalf("past the cap: %v, want its caller's cancellation", got.err)
	}
	if got := recv(t, underResult, "the detached call's caller"); !errors.Is(got.err, context.Canceled) {
		t.Fatalf("its caller stops waiting: %v", got.err)
	}
	if n := over.calls.Load(); n != 1 {
		t.Fatalf("the call past the cap ran %d times", n)
	}

	// The detached call is still running; let it finish and hand back its slot.
	if n := g.detached.Load(); n != 1 {
		t.Fatalf("detached count %d with one detached call running, want 1", n)
	}
	under.release()
	deadline := time.Now().Add(5 * time.Second)
	for g.detached.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("detached count stuck at %d", g.detached.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A panicking detached call still hands back its slot.
func TestMaxDetached_PanicReleasesTheSlot(t *testing.T) {
	g := New[int]("test", time.Minute, nil, WithMaxDetached(1))
	_, err := g.Do(context.Background(), "p", func(context.Context) (int, error) { panic("bug") })
	if !errors.Is(err, ErrPanicked) {
		t.Fatalf("got %v, want ErrPanicked", err)
	}
	if n := g.detached.Load(); n != 0 {
		t.Fatalf("detached count %d after a panic, want 0", n)
	}
}

// The zero Group works like singleflight's: coalescing, detached, bounded by the
// default timeout, and recovering a panic.
func TestZeroGroup_IsReadyToUse(t *testing.T) {
	var g Group[int]
	w := newGate(t)
	result := do(&g, context.Background(), w)
	recv(t, w.entered, "the shared call to start")
	w.release()
	if got := recv(t, result, "the result"); got.err != nil || got.v != 42 {
		t.Fatalf("got %v, %v", got.v, got.err)
	}

	_, err := g.Do(context.Background(), "p", func(context.Context) (int, error) { panic("bug") })
	if !errors.Is(err, ErrPanicked) {
		t.Fatalf("zero Group did not recover a panic: %v", err)
	}
}
