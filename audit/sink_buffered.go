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
	mu   sync.Mutex
	sink Sink
	// batch is sink when it takes a whole buffer in one write, nil otherwise.
	batch batchWriter

	// pending holds the buffered entries one after the other, each followed
	// by a newline, in the order they were accepted; ends[i] is where the
	// i-th ends in it, newline included. Both are emptied by a flush and
	// filled again in place: accepting an entry copies it and allocates
	// nothing.
	pending []byte
	ends    []int

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
func (bs *BufferedSink) Write(ctx context.Context, entry []byte) error {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	if bs.closed {
		return errSinkClosed
	}

	bs.pending = append(bs.pending, entry...)
	bs.pending = append(bs.pending, '\n')
	bs.ends = append(bs.ends, len(bs.pending))

	// Flush if buffer is full
	if len(bs.ends) >= bs.bufferSize {
		return bs.flushLocked(ctx)
	}

	return nil
}

// errSinkClosed refuses a write to a sink that has been closed.
var errSinkClosed = errors.New("sink is closed")

// Flush flushes the buffer to the underlying sink
func (bs *BufferedSink) Flush(ctx context.Context) error {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	// Allow flush even when closed (needed for final flush during Close)
	return bs.flushLocked(ctx)
}

// flushLocked flushes the buffer (must be called with lock held).
// On partial failure, only successfully written entries are removed from the buffer.
//
// A sink that takes a batch is handed the whole buffer in one write: the lock
// that every request's entry waits for is held for one write, not one per
// entry. Any other sink is written one entry at a time, without the newline,
// as if it were not buffered.
func (bs *BufferedSink) flushLocked(ctx context.Context) error {
	if len(bs.ends) == 0 {
		return nil
	}

	// written counts the entries the sink took whole.
	var written int
	var writeErr error
	if bs.batch != nil {
		var n int
		n, writeErr = bs.batch.WriteBatch(ctx, bs.pending)
		// An entry the write cut short is not written: it stays, whole. One
		// cut just before its newline is: the sink has all of it, and ends
		// the line before it writes anything else.
		written = sort.Search(len(bs.ends), func(i int) bool { return bs.ends[i]-1 > n })
	} else {
		start := 0
		for _, end := range bs.ends {
			// The entry without its newline, and with no room after it but
			// the newline's: a sink that appends to what it is handed writes
			// over nothing of the next entry.
			if writeErr = bs.sink.Write(ctx, bs.pending[start:end-1:end]); writeErr != nil {
				break
			}
			written++
			start = end
		}
	}

	bs.dropWritten(written)

	if writeErr != nil {
		return fmt.Errorf("failed to write buffered entry: %w", writeErr)
	}
	return nil
}

// dropWritten removes the first written entries from the buffer and moves the
// rest to its start, in their order. The buffer keeps its capacity.
func (bs *BufferedSink) dropWritten(written int) {
	if written == 0 {
		return
	}
	offset := bs.ends[written-1]
	bs.pending = bs.pending[:copy(bs.pending, bs.pending[offset:])]
	kept := bs.ends[:0]
	for _, end := range bs.ends[written:] {
		kept = append(kept, end-offset)
	}
	bs.ends = kept
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

// Close closes the buffered sink with a timeout to prevent hanging on shutdown
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

	// Flush remaining buffer with timeout context, then close the sink below
	// whether or not the flush succeeded: left open, its file would stay
	// beside the one the next device opens for the same path.
	ctx, cancel := context.WithTimeout(context.Background(), bs.closeTimeout)
	defer cancel()

	var failures []error
	if err := bs.Flush(ctx); err != nil {
		failures = append(failures, fmt.Errorf("failed to flush on close, %d entries are not written: %w", bs.held(), err))
	}
	if err := bs.sink.Close(); err != nil {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}

// held is how many entries the sink holds.
func (bs *BufferedSink) held() int {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	return len(bs.ends)
}

// Name returns the sink name
func (bs *BufferedSink) Name() string {
	return bs.sink.Name()
}

// Type returns the sink type
func (bs *BufferedSink) Type() string {
	return "buffered-" + bs.sink.Type()
}
