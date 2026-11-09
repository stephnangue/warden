// Package flight coalesces concurrent calls for the same key into one, and is the
// only package in this module that uses golang.org/x/sync/singleflight directly.
//
// singleflight alone leaves four rules to every caller, and missing any one is a
// bug in a gateway where the coalesced call is a credential mint or a login:
//
//   - The shared work must not run on the context of whichever request happened
//     to start it, or that request's client going away fails every other waiter.
//   - The work then needs a bound of its own, and must end when its owner stops
//     rather than outliving a seal or a step-down.
//   - Each caller must wait on its own context, not on the shared work.
//   - A panic in the work must become an error. With a waiting channel,
//     singleflight re-raises it on a fresh goroutine where nothing can recover
//     it, so a bug reached by one request would end the process.
//
// Group applies all four, and returns typed results. Where a caller who has not
// authenticated chooses the key, WithMaxDetached also caps how much detached work
// such callers can leave running.
package flight

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"sync/atomic"
	"time"

	"github.com/stephnangue/warden/logger"
	"golang.org/x/sync/singleflight"
)

// ErrPanicked is wrapped by the error every waiter receives when the shared work
// panicked.
var ErrPanicked = errors.New("shared call panicked")

// DefaultTimeout bounds each shared call of a Group that sets no timeout of its own.
const DefaultTimeout = 30 * time.Second

// Group coalesces concurrent calls by key. The zero value is ready to use: shared
// calls are bounded by DefaultTimeout and have no lifetime. New sets a name, a
// timeout and a lifetime. A Group is safe for concurrent use and must not be
// copied after first use.
type Group[T any] struct {
	sf          singleflight.Group
	name        string
	timeout     time.Duration
	log         *logger.GatedLogger
	lifetime    func() context.Context
	maxDetached int
	detached    atomic.Int64 // shared calls running detached right now
}

// Option configures a Group.
type Option func(*groupOptions)

type groupOptions struct {
	lifetime    func() context.Context
	maxDetached int
}

// WithMaxDetached lets at most n shared calls run detached at once. Past that, a
// new call is still shared, but runs on the context of the caller that started
// it, so that caller going away ends it, as a call that was never shared would.
//
// It is for a group whose key the caller chooses before anyone has checked who it
// is, such as a login keyed by the credential presented. Detached, each request
// sent and dropped at once would leave work running for up to the timeout, with no
// connection held to bound how many pile up. Refusing calls past the cap instead
// would let the same traffic lock everyone else out.
func WithMaxDetached(n int) Option {
	return func(o *groupOptions) { o.maxDetached = n }
}

// WithLifetime ends the shared work when the context lifetime returns is done:
// the owner stopping, the node sealing or stepping down. lifetime is called once
// per shared call, so it may return a context that changes over the owner's life.
// A nil context is ignored.
func WithLifetime(lifetime func() context.Context) Option {
	return func(o *groupOptions) { o.lifetime = lifetime }
}

// New builds a Group. name labels its errors and log lines. timeout bounds each
// shared call, which no caller's context does; a non-positive one means
// DefaultTimeout. log may be nil.
func New[T any](name string, timeout time.Duration, log *logger.GatedLogger, opts ...Option) *Group[T] {
	var o groupOptions
	for _, opt := range opts {
		opt(&o)
	}
	return &Group[T]{name: name, timeout: timeout, log: log, lifetime: o.lifetime, maxDetached: o.maxDetached}
}

// Do runs fn once for every caller that asks for key while a call is in flight,
// and returns its result to each.
//
// fn runs on a context that carries ctx's values but not its cancellation,
// bounded by the Group's timeout and ended by its lifetime; past WithMaxDetached's
// cap it keeps the cancellation of the caller that started it. The caller waits
// on its own ctx: when that ends first, Do returns ctx's error at once and the
// shared call carries on for the others. A panic in fn is logged with its stack
// and returned to every waiter as an error wrapping ErrPanicked.
//
// The result is shared: callers must not mutate it.
func (g *Group[T]) Do(ctx context.Context, key string, fn func(ctx context.Context) (T, error)) (T, error) {
	timeout := g.timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ch := g.sf.DoChan(key, func() (v any, err error) {
		defer g.recover(&err)

		base := context.WithoutCancel(ctx)
		if g.maxDetached > 0 {
			if g.detached.Add(1) > int64(g.maxDetached) {
				g.detached.Add(-1)
				base = ctx
			} else {
				defer g.detached.Add(-1)
			}
		}

		work, cancel := context.WithTimeout(base, timeout)
		defer cancel()
		if g.lifetime != nil {
			if life := g.lifetime(); life != nil {
				stop := context.AfterFunc(life, cancel)
				defer stop()
			}
		}
		return fn(work)
	})

	select {
	case res := <-ch:
		if res.Err != nil {
			var zero T
			return zero, res.Err
		}
		// Comma-ok: an interface T whose fn returned nil arrives as a nil any.
		v, _ := res.Val.(T)
		return v, nil
	case <-ctx.Done():
		var zero T
		return zero, ctx.Err()
	}
}

// Evict makes the next call for key start a new shared call even if one is in
// flight; callers already waiting on the old one still receive its result. It is
// for a caller that knows the in-flight result is stale. Do not call it after a
// failed Do: a failure is never kept, so the next call starts afresh anyway, and
// Evict would cut loose a newer call already in flight.
func (g *Group[T]) Evict(key string) { g.sf.Forget(key) }

func (g *Group[T]) recover(err *error) {
	r := recover()
	if r == nil {
		return
	}
	name := g.name
	if name == "" {
		name = "shared call"
	}
	if g.log != nil {
		g.log.Error(name+" panicked", logger.Any("panic", r), logger.String("stack", string(debug.Stack())))
	}
	*err = fmt.Errorf("%s: %w: %v", name, ErrPanicked, r)
}
