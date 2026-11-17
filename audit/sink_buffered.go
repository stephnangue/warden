package audit

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/stephnangue/warden/logger"
)

const (
	// DefaultCloseTimeout is the maximum time to wait for graceful shutdown
	DefaultCloseTimeout = 10 * time.Second
)

// batchWriter is a sink that takes several entries in one write.
type batchWriter interface {
	// WriteBatch writes batch, a run of entries each ended by a newline, and
	// returns how many of its bytes the sink took. Fewer than all of them
	// comes with an error.
	//
	// An entry is written once the sink has all of it but its newline: a
	// sink that stopped there ends the line itself before its next write, as
	// it does for an entry cut anywhere else.
	WriteBatch(ctx context.Context, batch []byte) (written int, err error)
}

// BufferedSink wraps a sink with buffering capabilities
type BufferedSink struct {
	sink Sink
	// batch is sink when it takes a whole buffer in one write, nil otherwise.
	batch batchWriter

	// mu guards what is buffered: pending, ends and closed. It is held for
	// the time it takes to copy an entry in, or to take the buffer out, and
	// never across a write to the sink: a request's entry does not wait for
	// the file.
	mu sync.Mutex

	// pending holds the buffered entries one after the other, each followed
	// by a newline, in the order they were accepted; ends[i] is where the
	// i-th ends in it, newline included. A flush exchanges them for out and
	// outEnds, emptied: accepting an entry copies it and allocates nothing.
	pending []byte
	ends    []int

	// inFlight is how many entries the flush in progress took out of the
	// buffer and has not yet written; zero between flushes. failing is set by
	// a flush the sink did not take whole and cleared by one it did. Both
	// are guarded by mu.
	inFlight int
	failing  bool

	// flushMu serialises the flushes, so that entries reach the sink in the
	// order they were accepted. It guards out and outEnds, the buffer a
	// flush is writing. It is taken before mu, never while holding it.
	flushMu sync.Mutex
	out     []byte
	outEnds []int

	bufferSize   int
	flushPeriod  time.Duration
	closeTimeout time.Duration
	done         chan struct{}
	closed       bool // Prevents operations after Close() starts
	wg           sync.WaitGroup
	logger       *logger.GatedLogger
}

// BufferedSinkConfig contains configuration for buffered sink
type BufferedSinkConfig struct {
	Sink         Sink
	BufferSize   int           // Number of entries to buffer before flushing
	FlushPeriod  time.Duration // Time between automatic flushes
	CloseTimeout time.Duration // Maximum time to wait for graceful shutdown
	Logger       *logger.GatedLogger
}

// NewBufferedSink creates a new buffered sink
func NewBufferedSink(config BufferedSinkConfig) (*BufferedSink, error) {
	if config.Sink == nil {
		return nil, fmt.Errorf("sink is required")
	}

	if config.BufferSize <= 0 {
		config.BufferSize = 100
	}

	if config.FlushPeriod <= 0 {
		config.FlushPeriod = 5 * time.Second
	}

	if config.CloseTimeout <= 0 {
		config.CloseTimeout = DefaultCloseTimeout
	}

	bs := &BufferedSink{
		sink:         config.Sink,
		ends:         make([]int, 0, config.BufferSize),
		bufferSize:   config.BufferSize,
		flushPeriod:  config.FlushPeriod,
		closeTimeout: config.CloseTimeout,
		done:         make(chan struct{}),
		logger:       config.Logger,
	}
	bs.batch, _ = config.Sink.(batchWriter)

	// Start periodic flush goroutine
	bs.wg.Add(1)
	go bs.periodicFlush()

	return bs, nil
}

// Write adds an entry to the buffer. The entry is copied: the caller may
// reuse it as soon as Write returns.
//
// A sink that fails with a full buffer refuses every write: each writer
// flushes in its turn, and is told if that fails too. The entries the sink
// could not take are kept to be written when it recovers, those of refused
// writes among them.
//
// One write is not refused that a sink writing under a single lock would
// have: one that comes while the first flush to fail is still in progress.
// Nothing says yet that the sink fails, and its entry is kept like those
// accepted before it.
func (bs *BufferedSink) Write(ctx context.Context, entry []byte) error {
	bs.mu.Lock()
	if bs.closed {
		bs.mu.Unlock()
		return errSinkClosed
	}

	bs.pending = append(bs.pending, entry...)
	bs.pending = append(bs.pending, '\n')
	bs.ends = append(bs.ends, len(bs.pending))
	// Flush if buffer is full. While the sink fails, what it holds counts,
	// the entries of the attempt in progress with the rest: the buffer is
	// empty for as long as that attempt lasts, and no less full for it.
	flush := len(bs.ends) >= bs.bufferSize || (bs.failing && bs.heldLocked() >= bs.bufferSize)
	bs.mu.Unlock()

	if flush {
		return bs.flush(ctx, true)
	}

	return nil
}

// errSinkClosed refuses a write to a sink that has been closed.
var errSinkClosed = errors.New("sink is closed")

// heldLocked is how many entries the sink holds: those buffered and those a
// flush is writing. Entries being written are still the sink's until the
// write succeeds: counted out, a sink whose write fails would look empty for
// as long as the write lasts. The caller holds mu.
func (bs *BufferedSink) heldLocked() int {
	return len(bs.ends) + bs.inFlight
}

// Flush flushes the buffer to the underlying sink
func (bs *BufferedSink) Flush(ctx context.Context) error {
	// Allow flush even when closed (needed for final flush during Close)
	return bs.flush(ctx, false)
}

// flush writes the buffer to the sink. On partial failure, only successfully
// written entries are removed from the buffer.
//
// The buffer is taken out under mu and written outside it, so entries are
// accepted while the sink writes. A writer that finds the buffer full waits
// here, behind the flush in progress: a sink slower than its writers holds
// them back, it does not let the buffer grow.
//
// ifFull is set by a writer: by the time it is its turn, another flush may
// have emptied the buffer, and there is nothing left for it to do. Not while
// the sink fails: then the writer makes its own attempt and is told how it
// went, so that every writer is refused until a flush succeeds.
func (bs *BufferedSink) flush(ctx context.Context, ifFull bool) error {
	bs.flushMu.Lock()
	defer bs.flushMu.Unlock()

	bs.mu.Lock()
	if len(bs.ends) == 0 || (ifFull && len(bs.ends) < bs.bufferSize && !bs.failing) {
		bs.mu.Unlock()
		return nil
	}
	bs.pending, bs.out = bs.out[:0], bs.pending
	bs.ends, bs.outEnds = bs.outEnds[:0], bs.ends
	bs.inFlight = len(bs.outEnds)
	bs.mu.Unlock()

	written, writeErr := bs.writeOut(ctx)

	bs.mu.Lock()
	bs.inFlight = 0
	if written < len(bs.outEnds) || writeErr != nil {
		bs.putBackLocked(written)
		bs.failing = true
	} else {
		bs.failing = false
	}
	bs.mu.Unlock()

	if writeErr != nil {
		return fmt.Errorf("failed to write buffered entry: %w", writeErr)
	}
	return nil
}

// writeOut writes out to the sink and returns how many of its entries the
// sink took whole. The caller holds flushMu.
//
// A sink that takes a batch is handed the whole buffer in one write. Any
// other sink is written one entry at a time, without the newline, as if it
// were not buffered.
func (bs *BufferedSink) writeOut(ctx context.Context) (written int, err error) {
	if bs.batch != nil {
		n, err := bs.batch.WriteBatch(ctx, bs.out)
		// An entry the write cut short is not written: it stays, whole. One
		// cut just before its newline is: the sink has all of it, and ends
		// the line before it writes anything else.
		return sort.Search(len(bs.outEnds), func(i int) bool { return bs.outEnds[i]-1 > n }), err
	}

	start := 0
	for _, end := range bs.outEnds {
		// The entry without its newline, and with no room after it but the
		// newline's: a sink that appends to what it is handed writes over
		// nothing of the next entry.
		if err := bs.sink.Write(ctx, bs.out[start:end-1:end]); err != nil {
			return written, err
		}
		written++
		start = end
	}
	return written, nil
}

// putBackLocked returns to the buffer the entries of out after the first
// written, which the sink did not take, in front of those accepted since the
// flush began: the order entries were accepted in is the order they are
// written in. The caller holds flushMu and mu.
func (bs *BufferedSink) putBackLocked(written int) {
	offset := 0
	if written > 0 {
		offset = bs.outEnds[written-1]
	}

	// Build the buffer in out: its unwritten entries moved to the start, then
	// what is pending.
	kept := copy(bs.out, bs.out[offset:])
	bs.out = append(bs.out[:kept], bs.pending...)
	ends := bs.outEnds[:0]
	for _, end := range bs.outEnds[written:] {
		ends = append(ends, end-offset)
	}
	for _, end := range bs.ends {
		ends = append(ends, end+kept)
	}

	bs.pending, bs.out = bs.out, bs.pending[:0]
	bs.ends, bs.outEnds = ends, bs.ends[:0]
}

// periodicFlush periodically flushes the buffer
func (bs *BufferedSink) periodicFlush() {
	defer bs.wg.Done()

	ticker := time.NewTicker(bs.flushPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ctx := context.Background()
			if err := bs.Flush(ctx); err != nil {
				if bs.logger != nil {
					bs.logger.Warn("periodic flush error",
						logger.String("sink", bs.sink.Name()),
						logger.Err(err),
					)
				}
			}
		case <-bs.done:
			return
		}
	}
}

// Close stops the sink: it accepts no entry from here on, writes what it
// holds, and closes the sink below. It reports the entries it could not
// write. It returns within about twice the close timeout whatever the sink
// below does, so that a file that no longer answers does not hold up a seal.
func (bs *BufferedSink) Close() error {
	// Mark as closed to prevent new writes
	bs.mu.Lock()
	if bs.closed {
		bs.mu.Unlock()
		return nil // Already closed
	}
	bs.closed = true
	bs.mu.Unlock()

	// Signal periodic flush to stop
	close(bs.done)

	// Wait for periodic flush goroutine with timeout
	waitDone := make(chan struct{})
	go func() {
		bs.wg.Wait()
		close(waitDone)
	}()

	select {
	case <-waitDone:
		// Goroutine stopped gracefully
	case <-time.After(bs.closeTimeout):
		if bs.logger != nil {
			bs.logger.Warn("timeout waiting for periodic flush goroutine to stop",
				logger.String("sink", bs.sink.Name()),
				logger.String("timeout", bs.closeTimeout.String()),
			)
		}
	}

	// The last flush, then the close of the sink below whether or not the
	// flush succeeded: left open, its file would stay beside the one the
	// next device opens for the same path. Both run off this goroutine. A
	// write that never returns holds flushMu for as long, and a seal waits
	// for this close.
	finished := make(chan error, 1)
	go func() {
		var failures []error
		if err := bs.Flush(context.Background()); err != nil {
			failures = append(failures, fmt.Errorf("failed to flush on close, %d entries are not written: %w", bs.held(), err))
		}
		if err := bs.sink.Close(); err != nil {
			failures = append(failures, err)
		}
		finished <- errors.Join(failures...)
	}()

	select {
	case err := <-finished:
		return err
	case <-time.After(bs.closeTimeout):
		return fmt.Errorf("gave up closing after %s, the sink still writing: %d entries are not written", bs.closeTimeout, bs.held())
	}
}

// held is how many entries the sink holds, buffered or being written.
func (bs *BufferedSink) held() int {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	return bs.heldLocked()
}

// Name returns the sink name
func (bs *BufferedSink) Name() string {
	return bs.sink.Name()
}

// Type returns the sink type
func (bs *BufferedSink) Type() string {
	return "buffered-" + bs.sink.Type()
}
